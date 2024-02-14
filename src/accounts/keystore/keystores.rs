use std::io::{Write};
use std::fs::File;
use serde::{Serialize, Deserialize};
use serde_json;
use chrono::Utc;
use uuid::Uuid;

use crate::types::types::{PrivateKey, PublicKey};
use crate::accounts::keystore::encrypt_private_key::encrypt_key;
use crate::constants::{DEFAULT_KEYSTORE_CIPHER, DEFAULT_KEYSTORE_DKLEN, DEFAULT_KEYSTORE_KDF, DEFAULT_KEYSTORE_N, DEFAULT_KEYSTORE_P, DEFAULT_KEYSTORE_R};

pub fn generate_keystore() -> Result<(), Box<dyn std::error::Error>> {
    let (iv, ciphertext, salt, public_key, mac) = encrypt_key()?;

    let uuid_id = uuid::Uuid::new_v4();

    let keystore = Keystore {
        version: 3,
        id: uuid_id,
        address: public_key,
        Crypto: Crypto {
            cipher: DEFAULT_KEYSTORE_CIPHER.to_string(),
            cipherparams: Cipherparams {
                iv,
            },
            ciphertext: ciphertext,
            kdf: DEFAULT_KEYSTORE_KDF.to_string(),
            kdfparams: Kdfparams {
                dklen: DEFAULT_KEYSTORE_DKLEN,
                n: 2u32.pow(DEFAULT_KEYSTORE_N as u32),
                p: DEFAULT_KEYSTORE_P,
                r: DEFAULT_KEYSTORE_R,
                salt
            },
            mac,
        },
    };
    make_file(keystore);
    Ok(())
}



fn make_file(keystore: Keystore) -> std::io::Result<()> {
    let now = Utc::now();
    let file_name = format!("UTC--{}--{}.txt", now.format("%Y-%m-%dT%H-%M-%S.%fZ"), keystore.address);
    let mut file = File::create(file_name)?;

    let serialized = serde_json::to_string_pretty(&keystore).expect("JSON 직렬화 실패");

    file.write_all(serialized.as_bytes())?;

    Ok(())
}

#[derive(Serialize, Deserialize)]
struct Keystore {
    version : u8,
    id : Uuid,
    address: String,
    Crypto: Crypto
}

#[derive(Serialize, Deserialize)]
struct Crypto {
    cipher : String,
    cipherparams : Cipherparams,
    ciphertext: String,
    kdf : String,                   // 암호화 알고리즘 이름
    kdfparams: Kdfparams,
    mac: String
}

#[derive(Serialize, Deserialize)]
struct Cipherparams {
    iv :String
}

#[derive(Serialize, Deserialize)]
struct Kdfparams {
    dklen: usize,                      // Derived Key Length의 약자입니다. 결과값의 길이(byte)가 됩니다. 32여야함.
    salt: String,                   // 32byte의 랜덤값.
    n : u32,                        // CPU/memory 비용
    r : u32,
    p : u32,
}