use crate::common::peer::sealer::Raw;
use crate::common::suite::peers::packet::Error;
use rustls::quic::{Connection, KeyChange};

#[derive(Default)]
pub(super) struct Wire {
    pub output: [Vec<u8>; 3],
    pub read: Option<Raw>,
    pub write: Option<Raw>,
    pub early: Option<Raw>,
    pub application: Option<(Raw, Raw)>,
    epoch: usize,
}

impl Wire {
    pub(super) fn write(&mut self, tls: &mut Connection, next: u64) -> Result<(), Error> {
        loop {
            match tls.write_hs(&mut self.output[self.epoch]) {
                Some(KeyChange::Handshake { keys }) => {
                    self.read = Some(Raw::from_keys(keys.remote, 0).map_err(Error::Key)?);
                    self.write = Some(Raw::from_keys(keys.local, 0).map_err(Error::Key)?);
                    self.epoch = 1;
                }
                Some(KeyChange::OneRtt { keys, .. }) => {
                    self.early = None;
                    self.application = Some((
                        Raw::from_keys(keys.remote, 0).map_err(Error::Key)?,
                        Raw::from_keys(keys.local, next).map_err(Error::Key)?,
                    ));
                    self.epoch = 2;
                }
                None => return Ok(()),
            }
        }
    }
}
