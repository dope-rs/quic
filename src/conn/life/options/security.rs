use crate::security::secrets;

#[derive(Default)]
pub struct Security {
    pub(crate) stateless_reset_secret: Option<secrets::Reset>,
    pub(crate) require_address_validation: bool,
    pub(crate) retry_token_secret: Option<secrets::Retry>,
}

impl Security {
    pub fn reset(mut self, value: Option<[u8; 32]>) -> Self {
        self.stateless_reset_secret = value.map(secrets::Reset);
        self
    }

    pub fn retry(mut self, secret: [u8; 32]) -> Self {
        self.require_address_validation = true;
        self.retry_token_secret = Some(secrets::Retry(secret));
        self
    }

    pub fn validation(mut self, secret: [u8; 32]) -> Self {
        self.retry_token_secret = Some(secrets::Retry(secret));
        self
    }
}
