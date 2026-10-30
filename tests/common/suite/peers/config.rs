use crate::common::peer;
use dope_quic::conn::life::options::Options;
use dope_quic::proto::param;
use peer::{Config, Pair, Setup};
use rustls::{pki_types::UnixTime, time_provider::TimeProvider};

#[derive(Debug)]
pub struct FixedTime(pub Option<UnixTime>);

impl TimeProvider for FixedTime {
    fn current_time(&self) -> Option<UnixTime> {
        self.0
    }
}

pub fn try_budget(bytes: usize, resident: usize, parts: usize) -> Result<Pair, Setup> {
    let client = Config::default()
        .try_build()?
        .into_builder()
        .streams(|streams| {
            streams
                .send_bytes(bytes)
                .resident(resident)
                .send_parts(parts)
        })
        .try_build()
        .map_err(Setup::Options)?;
    Pair::try_new(Config::default().try_build()?, client)
}

pub fn try_packet() -> Result<Pair, Setup> {
    let options = || {
        Config::default()
            .try_build()?
            .into_builder()
            .transport(|path| path.max_pmtu(1200))
            .try_build()
            .map_err(Setup::Options)
    };
    Pair::try_new(options()?, options()?)
}

pub fn try_bounds() -> Result<Options, Setup> {
    let params = param::Set::builder()
        .idle_ms(30_000)
        .initial_data(1 << 24)
        .local_bidi(1 << 16)
        .remote_bidi(1 << 16)
        .bidi_count(512)
        .try_build()
        .map_err(Setup::Params)?;
    Options::try_from(params).map_err(Setup::Options)
}

pub fn try_ceiling() -> Result<Options, Setup> {
    Config::default()
        .try_build()?
        .into_builder()
        .journals(|journals| {
            journals
                .packet::<{ u16::MAX as usize }>()
                .crypto::<{ u16::MAX as usize }>()
                .control::<{ u16::MAX as usize }>()
                .stream::<{ u16::MAX as usize }>()
        })
        .try_build()
        .map_err(Setup::Options)
}

/// Transport configurations used by packet recovery and allocation fixtures.
pub trait Parameters: Sized {
    fn try_pto() -> Result<Self, Setup>;
    fn try_steady() -> Result<Self, Setup>;
    fn try_send() -> Result<Self, Setup>;
    fn try_recv() -> Result<Self, Setup>;
    fn try_credit() -> Result<Self, Setup>;
    fn try_journal() -> Result<Self, Setup>;
}

impl Parameters for Options {
    fn try_pto() -> Result<Self, Setup> {
        let params = param::Set::builder()
            .idle_ms(30_000)
            .datagram(Some(65535))
            .try_build()
            .map_err(Setup::Params)?;
        Options::try_from(params).map_err(Setup::Options)
    }

    fn try_steady() -> Result<Self, Setup> {
        let params = param::Set::builder()
            .idle_ms(30_000)
            .initial_data(1 << 20)
            .local_bidi(1 << 20)
            .remote_bidi(1 << 20)
            .stream_uni(1 << 20)
            .bidi_count(8)
            .uni_count(8)
            .try_build()
            .map_err(Setup::Params)?;
        Options::try_from(params).map_err(Setup::Options)
    }

    fn try_send() -> Result<Self, Setup> {
        let options = Self::try_steady()?;
        let params = options
            .params()
            .to_builder()
            .bidi_count(0)
            .uni_count(8)
            .try_build()
            .map_err(Setup::Params)?;
        options
            .into_builder()
            .transport(|wire| wire.params(params))
            .streams(|streams| streams.local_bidi(0).local_uni(2))
            .try_build()
            .map_err(Setup::Options)
    }

    fn try_recv() -> Result<Self, Setup> {
        let options = Self::try_steady()?;
        let params = options
            .params()
            .to_builder()
            .stream_uni(64)
            .bidi_count(0)
            .uni_count(2)
            .try_build()
            .map_err(Setup::Params)?;
        options
            .into_builder()
            .transport(|wire| wire.params(params))
            .streams(|streams| streams.local_bidi(0).local_uni(2))
            .try_build()
            .map_err(Setup::Options)
    }

    fn try_credit() -> Result<Self, Setup> {
        Self::try_steady()?
            .into_builder()
            .streams(|streams| streams.send_bytes(1).resident(64).send_parts(4))
            .try_build()
            .map_err(Setup::Options)
    }

    fn try_journal() -> Result<Self, Setup> {
        Config::default()
            .try_build()?
            .into_builder()
            .journals(|journals| journals.packet::<2>())
            .try_build()
            .map_err(Setup::Options)
    }
}
