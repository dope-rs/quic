#[derive(Debug, Clone)]
pub struct Ticket {
    pub ticket_lifetime: u32,
    pub ticket_age_add: u32,
    pub ticket_nonce: Vec<u8>,
    pub ticket: Vec<u8>,
    pub psk: [u8; 32],
}
