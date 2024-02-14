/// The size (in bytes) of a private key.
pub const PRIVATE_KEY_SIZE: usize = 32;
/// The size (in bytes) of a public key.
pub const PUBLIC_KEY_SIZE: usize = 20;

// keystore enscrypt
pub const DEFAULT_KEYSTORE_VERSION:u8 = 3;
pub const DEFAULT_KEYSTORE_CIPHER: &str = "aes-128-ctr";
pub const DEFAULT_KEYSTORE_KDF: &str = "scrypt";
pub const DEFAULT_KEYSTORE_DKLEN: usize = 32;
pub const DEFAULT_KEYSTORE_N: u8 = 13;
pub const DEFAULT_KEYSTORE_R: u32 = 8;
pub const DEFAULT_KEYSTORE_P: u32 = 1;

