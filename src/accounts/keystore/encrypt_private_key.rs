use scrypt::{scrypt, Params};
use crate::types::types::{PrivateKey};

use aes::Aes128;
use aes::cipher::{
    KeyInit,

};
use hex::encode;
use cipher::{InnerIvInit, StreamCipherCore};
use rand::{RngCore, thread_rng};
use crate::constants::{DEFAULT_KEYSTORE_DKLEN, DEFAULT_KEYSTORE_N, DEFAULT_KEYSTORE_P, DEFAULT_KEYSTORE_R};
use crate::accounts::generate_key::generate_key;
use keccak_hash::{ keccak};
use crate::accounts::keystore::keystores::input_password;

#[derive(Debug)]
pub struct Aes128Ctr {
    inner: ctr::CtrCore<Aes128, ctr::flavors::Ctr128BE>,
}

impl Aes128Ctr {
    pub(crate) fn new(key: &[u8], iv: &[u8]) -> Result<Self, cipher::InvalidLength> {
        let cipher = aes::Aes128::new_from_slice(key).unwrap();
        let inner = ctr::CtrCore::inner_iv_slice_init(cipher, iv).unwrap();
        Ok(Self { inner })
    }

    pub(crate) fn apply_keystream(self, buf: &mut [u8]) {
        self.inner.apply_keystream_partial(buf.into());
    }
}

pub fn encrypt_key() -> Result<(String, String, String, String, String), Box<dyn std::error::Error>>  {
    let (scrypt_key, salt) = scrypt_password()?;
    let (private_key, public_key) = generate_key();

    let (iv,ciphertext) =  aes_key(private_key, scrypt_key.clone())?;

    let mut combined_key = scrypt_key[16..32].to_vec();
    combined_key.extend_from_slice(&ciphertext);

    let mac = keccak(combined_key);

    // let mac = keccak256();
    Ok((encode(iv), encode(ciphertext), encode(salt), encode(public_key), encode(mac)))
}

fn scrypt_password() -> Result<(Vec<u8>, [u8; 32]), Box<dyn std::error::Error>> {
    let password = input_password();

    let mut key = vec![0u8; DEFAULT_KEYSTORE_DKLEN];
    let mut salt = [0u8; 32];
    thread_rng().fill_bytes(&mut salt);
    let scrypt_params = Params::new(DEFAULT_KEYSTORE_N, DEFAULT_KEYSTORE_R, DEFAULT_KEYSTORE_P, DEFAULT_KEYSTORE_DKLEN)?;
    scrypt(password.as_ref(), &salt, &scrypt_params, key.as_mut_slice())?;

    Ok((key, salt))
}



fn aes_key(private_key: PrivateKey, scrypt_key: Vec<u8>)-> Result<(Vec<u8>,Vec<u8>), Box<dyn std::error::Error>> {
    let mut iv = vec![0u8; 16];
    thread_rng().fill_bytes(iv.as_mut_slice());

    let encryptor = Aes128Ctr::new(&scrypt_key[..16], &iv[..16]);

    match encryptor {
        Ok(encryptor) => {
            let mut ciphertext = private_key.as_ref().to_vec();
            encryptor.apply_keystream(&mut ciphertext);

            Ok((iv,ciphertext))
        }
        Err(_e) => {
            Err(Box::<dyn std::error::Error>::from("InvalidLength"))
        }
        // }
    }
}
