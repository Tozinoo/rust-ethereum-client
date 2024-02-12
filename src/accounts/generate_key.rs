use keccak_hash::{H256, keccak};
use secp256k1::Secp256k1;
use crate::types::types::{PrivateKey, PublicKey};

/// pub struct SecretKey([u8; constants::SECRET_KEY_SIZE]);
/// SECRET_KEY_SIZE: usize = 32;
pub fn generate_key() -> (PrivateKey, PublicKey) {
    let secp = Secp256k1::new();
    let (secret_key, public_key) = secp.generate_keypair(&mut rand::thread_rng());

    // publc key
    let serialized_public_key = public_key.serialize_uncompressed()[1..].to_vec();
    let public_key = keccak(serialized_public_key);


    (secret_key.secret_bytes(), slice_last_20_bytes(public_key))
}

fn slice_last_20_bytes(public_key: H256) -> PublicKey {
    let public_key_bytes = public_key.as_bytes();
    let last_20_bytes: PublicKey = public_key_bytes[12..32].try_into().expect("Slice with incorrect length");
    last_20_bytes
}