use shin::hash::HashAlg;
use shin::kdf::Hkdf;

const ALG: HashAlg = HashAlg::Sha256;

pub const INITIAL_SALT_V1: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

pub const HASH_LEN: usize = 32;
pub const KEY_LEN: usize = 16;
pub const IV_LEN: usize = 12;
pub const HP_KEY_LEN: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitialSecrets {
    pub client: [u8; HASH_LEN],
    pub server: [u8; HASH_LEN],
}

impl InitialSecrets {
    pub fn from_dcid(dcid: &[u8]) -> Self {
        let initial_secret = Hkdf::extract(ALG, &INITIAL_SALT_V1, dcid);
        let mut client = [0u8; HASH_LEN];
        Hkdf::expand_label(
            ALG,
            initial_secret.as_slice(),
            "client in",
            &[],
            &mut client,
        );
        let mut server = [0u8; HASH_LEN];
        Hkdf::expand_label(
            ALG,
            initial_secret.as_slice(),
            "server in",
            &[],
            &mut server,
        );
        Self { client, server }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketKeys {
    pub key: [u8; KEY_LEN],
    pub iv: [u8; IV_LEN],
    pub hp: [u8; HP_KEY_LEN],
}

impl PacketKeys {
    pub fn aes_128(secret: &[u8]) -> Self {
        let mut key = [0u8; KEY_LEN];
        let mut iv = [0u8; IV_LEN];
        let mut hp = [0u8; HP_KEY_LEN];
        Hkdf::expand_label(ALG, secret, "quic key", &[], &mut key);
        Hkdf::expand_label(ALG, secret, "quic iv", &[], &mut iv);
        Hkdf::expand_label(ALG, secret, "quic hp", &[], &mut hp);
        Self { key, iv, hp }
    }
}
