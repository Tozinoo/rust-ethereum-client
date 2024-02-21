use std::{fs, io};
use std::error::Error;
use std::io::{Read, Write};
use std::fs::File;
use std::path::Path;
use serde::{Serialize, Deserialize};
use serde_json;
use chrono::Utc;
use scrypt::{Params, scrypt};
use uuid::Uuid;
use keccak_hash::{ keccak};
use hex::{encode,decode};

use crate::accounts::keystore::encrypt_private_key::{Aes128Ctr, encrypt_key};
use crate::constants::{DEFAULT_KEYSTORE_VERSION, DEFAULT_KEYSTORE_CIPHER, DEFAULT_KEYSTORE_DKLEN, DEFAULT_KEYSTORE_KDF, DEFAULT_KEYSTORE_N, DEFAULT_KEYSTORE_P, DEFAULT_KEYSTORE_R};

#[derive(Serialize, Deserialize, Debug)]
pub struct Keystore {
    pub(crate) version : u8,
    id : Uuid,
    address: String,
    crypto: Crypto
}

#[derive(Serialize, Deserialize, Debug)]
struct Crypto {
    cipher : String,
    cipherparams : Cipherparams,
    ciphertext: String,
    kdf : String,                   // 암호화 알고리즘 이름
    kdfparams: Kdfparams,
    mac: String
}

#[derive(Serialize, Deserialize, Debug)]
struct Cipherparams {
    iv :String
}

#[derive(Serialize, Deserialize, Debug)]
struct Kdfparams {
    dklen: usize,                      // Derived Key Length의 약자입니다. 결과값의 길이(byte)가 됩니다. 32여야함.
    salt: String,                   // 32byte의 랜덤값.
    n : u32,                        // CPU/memory 비용
    r : u32,
    p : u32,
}


fn make_file(keystore: Keystore) -> std::io::Result<()> {
    let now = Utc::now();
    fs::create_dir_all("keystore")?;
    let file_name = format!("keystore/UTC--{}--{}.txt", now.format("%Y-%m-%dT%H-%M-%S.%fZ"), keystore.address);
    let mut file = File::create(file_name)?;

    let serialized = serde_json::to_string_pretty(&keystore).expect("JSON 직렬화 실패");

    file.write_all(serialized.as_bytes())?;

    Ok(())
}

fn read_file(path: &Path) -> io::Result<Keystore> {
    let mut file = fs::File::open(path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    let keystore:Keystore = serde_json::from_str(&contents).expect("can't deserialize");

    Ok(keystore)
}

pub fn input_password() -> String {
    print!("Please enter any key to generate a private key : "); //
    io::stdout().flush().expect("Failed to flush stdout."); //

    let mut password = String::new();

    io::stdin()
        .read_line(&mut password)
        .expect("Failed to read input....");

    password.trim().to_string()
}

pub fn generate_keystore() -> Result<(), Box<dyn std::error::Error>> {
    let (iv, ciphertext, salt, public_key, mac) = encrypt_key()?;

    let uuid_id = uuid::Uuid::new_v4();

    let keystore = Keystore {
        version: DEFAULT_KEYSTORE_VERSION,
        id: uuid_id,
        address: public_key,
        crypto: Crypto {
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
            mac: mac
        },
    };
    let _ = make_file(keystore);
    Ok(())
}




pub fn decrypt_keystore_file(path : &Path) -> Result<Vec<u8>, Box<dyn Error>> {
    if let Ok(keystore) = read_file(path) {
        let password = input_password();
        let scrypt_key = match keystore.crypto.kdfparams {
            crate::accounts::keystore::keystores::Kdfparams {
                dklen,
                n,
                p,
                r,
                salt,
            } => {
                let mut scrypt_key = vec![0u8; dklen];
                let log_n = (n as f32).log2().ceil() as u8;
                let salt = hex::decode(&salt).expect("Decoding failed");

                let scrypt_params = Params::new(log_n, r, p, dklen)?;

                scrypt(password.as_ref(), &salt, &scrypt_params, scrypt_key.as_mut_slice())?;
                scrypt_key
            }
        };
        // Derive the MAC from the derived key and ciphertext.
        let mut combined_key = scrypt_key[16..32].to_vec();
        let mut ciphertext = hex::decode(&keystore.crypto.ciphertext).expect("Decoding failed");
        combined_key.append(&mut ciphertext);
        let derived_mac = keccak(combined_key);
        if encode(derived_mac) != keystore.crypto.mac {
            return Err(Box::<dyn std::error::Error>::from("InvalidLength"));
        }
        let mut iv:[u8;16] = [0;16];
        hex::decode_to_slice(&keystore.crypto.cipherparams.iv,&mut iv).expect("Decoding failed");
        // Decrypt the private key bytes using AES-128-CTR
        let decryptor =
            Aes128Ctr::new(&scrypt_key[..16], &iv[..16]).expect("invalid length");
        let mut pk = decode(keystore.crypto.ciphertext).expect("Decoding failed");
        decryptor.apply_keystream(&mut pk);
        Ok(pk)


    } else {
         Err(Box::<dyn std::error::Error>::from("InvalidLength"))
    }

}

