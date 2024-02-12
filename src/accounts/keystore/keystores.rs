use std::io::{self, Write};
use std::fs::File;
use serde::{Serialize, Deserialize};
use serde_json;
use chrono::Utc;

use crate::types::types::{PrivateKey, PublicKey};
use crate::accounts::keystore::encrypt_private_key::scrypt_password;


pub fn generate_keystore(private_key: PrivateKey, public_key: PublicKey ,password: String) -> std::io::Result<()> {
    let signed_key:String = sign_private_key(private_key);
    scrypt_password();
    make_file(signed_key, public_key);
    Ok(())
}

fn sign_private_key(private_key:PrivateKey) -> String {
    String::from("123")
}


fn make_file(signed_key:String, public_key: PublicKey) -> std::io::Result<()> {
    let now = Utc::now();
    let file_name = format!("UTC--{}--{}.txt", now.format("%Y-%m-%dT%H-%M-%S.%fZ"), hex::encode(public_key));
    let mut file = File::create(file_name)?;

    let a = Cipherparams{
        iv:signed_key
    };

    let serialized = serde_json::to_string_pretty(&a).expect("JSON 직렬화 실패");

    file.write_all(serialized.as_bytes())?;

    Ok(())
}

#[derive(Serialize, Deserialize)]
struct Keystore {
    version : u8,
    id : String,
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
    dklen: u8,                      // Derived Key Length의 약자입니다. 결과값의 길이(byte)가 됩니다. 32여야함.
    salt: String,                   // 32byte의 랜덤값.
    n : u32,                        // CPU/memory 비용
    r : u8,
    p : u8,
}