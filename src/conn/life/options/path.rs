use crate::conn;
use crate::conn::life::options::builder;
use crate::proto::{datagram, param, recovery::pmtud};
use crate::wire::varint;
use conn::stream;

pub struct Path {
    params: param::Set,
    max_pmtu: u64,
}

pub(in crate::conn) struct Transport {
    params: param::Set,
    max_pmtu: pmtud::Maximum,
}

#[derive(Clone, Copy)]
pub(in crate::conn) struct Flow<'a>(&'a Transport);

#[derive(Clone, Copy)]
pub(in crate::conn) struct Identity<'a>(&'a Transport);

impl Path {
    pub(super) const DEFAULT: Self = Self {
        params: param::Set::DEFAULT,
        max_pmtu: pmtud::DEFAULT_MAX_PMTU,
    };

    pub fn params(mut self, value: param::Set) -> Self {
        self.params = value;
        self
    }

    pub fn max_pmtu(mut self, value: u64) -> Self {
        self.max_pmtu = value;
        self
    }

    pub(super) const fn try_prove(
        self,
    ) -> Result<(Transport, [stream::Count; 2]), builder::Invalid> {
        let Some(max_pmtu) = pmtud::Maximum::new(self.max_pmtu) else {
            return Err(builder::Invalid::Pmtu {
                actual: self.max_pmtu,
                minimum: pmtud::BASE_PMTU,
                maximum: pmtud::MAX_PMTU,
            });
        };
        let peer = match self.try_flow() {
            Ok(peer) => peer,
            Err(error) => return Err(error),
        };
        let actual = self.params.identity().cid_limit();
        if actual > conn::MAX_ACTIVE_CONNECTION_IDS as u64 {
            return Err(builder::Invalid::ConnectionIds {
                actual,
                minimum: 2,
                maximum: conn::MAX_ACTIVE_CONNECTION_IDS as u64,
            });
        }
        Ok((
            Transport {
                params: self.params,
                max_pmtu,
            },
            peer,
        ))
    }

    const fn try_flow(&self) -> Result<[stream::Count; 2], builder::Invalid> {
        let flow = self.params.flow();
        let actual = flow.initial_data().get();
        if actual > conn::MAX_FLOW_CONTROL_CREDIT {
            return Err(builder::Invalid::InitialData {
                actual,
                minimum: 0,
                maximum: conn::MAX_FLOW_CONTROL_CREDIT,
            });
        }
        let actual = flow.local_bidi().get();
        if actual > conn::MAX_FLOW_CONTROL_CREDIT {
            return Err(builder::Invalid::LocalBidiData {
                actual,
                minimum: 0,
                maximum: conn::MAX_FLOW_CONTROL_CREDIT,
            });
        }
        let actual = flow.remote_bidi().get();
        if actual > conn::MAX_FLOW_CONTROL_CREDIT {
            return Err(builder::Invalid::RemoteBidiData {
                actual,
                minimum: 0,
                maximum: conn::MAX_FLOW_CONTROL_CREDIT,
            });
        }
        let actual = flow.stream_uni().get();
        if actual > conn::MAX_FLOW_CONTROL_CREDIT {
            return Err(builder::Invalid::StreamUniData {
                actual,
                minimum: 0,
                maximum: conn::MAX_FLOW_CONTROL_CREDIT,
            });
        }
        let actual = flow.bidi_count();
        let Some(bidi) = stream::Count::from_u64(actual) else {
            return Err(builder::Invalid::PeerBidi {
                actual,
                minimum: 0,
                maximum: conn::MAX_STREAMS,
            });
        };
        let actual = flow.uni_count();
        let Some(uni) = stream::Count::from_u64(actual) else {
            return Err(builder::Invalid::PeerUni {
                actual,
                minimum: 0,
                maximum: conn::MAX_STREAMS,
            });
        };
        Ok([bidi, uni])
    }
}

impl Transport {
    pub(in crate::conn) const fn params(&self) -> &param::Set {
        &self.params
    }

    pub(in crate::conn) const fn flow(&self) -> Flow<'_> {
        Flow(self)
    }

    pub(in crate::conn) const fn identity(&self) -> Identity<'_> {
        Identity(self)
    }

    pub(in crate::conn) const fn max_pmtu(&self) -> pmtud::Maximum {
        self.max_pmtu
    }

    pub(in crate::conn) fn cap_udp(&mut self, cap: datagram::Size) {
        self.max_pmtu = self.max_pmtu.cap(cap);
        self.params.cap_udp(cap);
    }

    pub(super) fn into_draft(self) -> Path {
        Path {
            params: self.params,
            max_pmtu: self.max_pmtu.get(),
        }
    }

    pub(super) fn copy(&self) -> Self {
        Self {
            params: self.params.clone(),
            max_pmtu: self.max_pmtu,
        }
    }
}

impl Flow<'_> {
    pub(in crate::conn) const fn initial_data(self) -> varint::VarInt {
        self.0.params.flow().initial_data()
    }

    pub(in crate::conn) const fn local_bidi(self) -> varint::VarInt {
        self.0.params.flow().local_bidi()
    }

    pub(in crate::conn) const fn remote_bidi(self) -> varint::VarInt {
        self.0.params.flow().remote_bidi()
    }

    pub(in crate::conn) const fn stream_uni(self) -> varint::VarInt {
        self.0.params.flow().stream_uni()
    }

    pub(in crate::conn) const fn datagram(self) -> Option<u64> {
        self.0.params.flow().datagram()
    }
}

impl Identity<'_> {
    pub(in crate::conn) const fn is_fixed(self) -> bool {
        self.0.params.identity().is_fixed()
    }

    pub(in crate::conn) const fn cid_limit(self) -> u64 {
        self.0.params.identity().cid_limit()
    }
}

impl Default for Path {
    fn default() -> Self {
        Self::DEFAULT
    }
}

const _: () = {
    assert!(std::mem::size_of::<Transport>() == std::mem::size_of::<Path>());
    assert!(std::mem::size_of::<Flow<'static>>() == std::mem::size_of::<usize>());
    assert!(std::mem::size_of::<Identity<'static>>() == std::mem::size_of::<usize>());
};
