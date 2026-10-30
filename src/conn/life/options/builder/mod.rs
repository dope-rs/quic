mod invalid;

pub use invalid::Invalid;

use crate::conn::life;
use life::options;

/// Unchecked construction state promoted only by [`Builder::try_build`].
#[must_use = "connection-option builders must be promoted with try_build"]
pub struct Builder {
    pub(super) path: options::Path,
    pub(super) dgrams: options::Dgram,
    pub(super) streams: options::Streams,
    pub(super) journals: options::Journals,
    pub(super) security: options::Security,
}

impl Builder {
    pub fn transport(mut self, f: impl FnOnce(options::Path) -> options::Path) -> Self {
        self.path = f(self.path);
        self
    }

    pub fn datagrams(mut self, f: impl FnOnce(options::Dgram) -> options::Dgram) -> Self {
        self.dgrams = f(self.dgrams);
        self
    }

    pub fn streams(mut self, f: impl FnOnce(options::Streams) -> options::Streams) -> Self {
        self.streams = f(self.streams);
        self
    }

    pub fn journals(mut self, f: impl FnOnce(options::Journals) -> options::Journals) -> Self {
        self.journals = f(self.journals);
        self
    }

    pub fn security(mut self, f: impl FnOnce(options::Security) -> options::Security) -> Self {
        self.security = f(self.security);
        self
    }

    pub fn try_build(self) -> Result<options::Options, Invalid> {
        let Self {
            path,
            dgrams,
            streams,
            journals,
            security,
        } = self;
        let (path, peer) = path.try_prove()?;
        let dgrams = dgrams.try_prove()?;
        let streams = streams.try_prove(peer)?;
        Ok(options::Options {
            transport: path,
            datagrams: dgrams,
            streams,
            journals: journals.promote(),
            security,
        })
    }
}
