use std::io::{self, Read, Write};
use scrypt::{scrypt, Params, password_hash::{PasswordHasher, SaltString}};

use aes::Aes128;
use aes::cipher::{
    BlockCipher, BlockEncrypt, BlockDecrypt, KeyInit,
    generic_array::GenericArray,
};
use hex::encode;
use cipher::{InnerIvInit, InvalidLength, StreamCipherCore};
use rand::{RngCore, thread_rng};
use secp256k1::SecretKey;
use serde::{Deserialize, Serialize};
use uuid::uuid;
use crate::constants::{DEFAULT_KEYSTORE_DKLEN, DEFAULT_KEYSTORE_N, DEFAULT_KEYSTORE_P, DEFAULT_KEYSTORE_R};
use crate::accounts::generate_key::generate_key;

#[derive(Debug)]
struct Aes128Ctr {
    inner: ctr::CtrCore<Aes128, ctr::flavors::Ctr128BE>,
}

impl Aes128Ctr {
    fn new(key: &[u8], iv: &[u8]) -> Result<Self, cipher::InvalidLength> {
        let cipher = aes::Aes128::new_from_slice(key).unwrap();
        let inner = ctr::CtrCore::inner_iv_slice_init(cipher, iv).unwrap();
        Ok(Self { inner })
    }

    fn apply_keystream(self, buf: &mut [u8]) {
        self.inner.apply_keystream_partial(buf.into());
    }
}


use crate::types::types::{PrivateKey, PublicKey};

pub fn encrypt_key() -> Result<(String, String, String, String), Box<dyn std::error::Error>>  {
    let (scrypt_key, salt) = scrypt_password()?;
    let (private_key, public_key) = generate_key();

    let (iv,ciphertext) =  aes_key(private_key, scrypt_key)?;
    Ok((encode(iv), encode(ciphertext), encode(salt), encode(public_key)))
}

fn scrypt_password() -> Result<(Vec<u8>, [u8; 32]), Box<dyn std::error::Error>> {
    let password = input_password();

    let mut key = vec![0u8; DEFAULT_KEYSTORE_DKLEN];

    let mut salt = [0u8; 32];
    thread_rng().fill_bytes(&mut salt);

    let scrypt_params = Params::new(DEFAULT_KEYSTORE_N,DEFAULT_KEYSTORE_P,DEFAULT_KEYSTORE_R, DEFAULT_KEYSTORE_DKLEN)?;
    scrypt(password.as_ref(), &salt, &scrypt_params, key.as_mut_slice())?;

    Ok((key, salt))
}

fn input_password() -> String {
    print!("Please enter any key to generate a private key : "); //
    io::stdout().flush().expect("Failed to flush stdout."); //

    let mut password = String::new();

    io::stdin()
        .read_line(&mut password)
        .expect("Failed to read input....");

    password.trim().to_string()
}

fn aes_key(private_key: PrivateKey, scrypt_key: Vec<u8>)-> Result<(Vec<u8>,Vec<u8>), Box<dyn std::error::Error>> {
    let mut iv = vec![0u8; 16];
    thread_rng().fill_bytes(iv.as_mut_slice());

    let encryptor = Aes128Ctr::new(&private_key[..16], &iv);

    match encryptor {
        Ok(encryptor) => {
            let mut ciphertext = private_key.as_ref().to_vec();
            encryptor.apply_keystream(&mut ciphertext);

            Ok((iv,ciphertext))
        }
        Err(e) => {
            Err(Box::<dyn std::error::Error>::from("InvalidLength"))
        }
        // }
    }
}




//     // Initialize cipher
//     let cipher = Aes128::new_from_slice(&private_key[..16]);
//     println!("{:?}", cipher);
//     let block_copy = block.clone();
//
// // Encrypt block in-place
//     match cipher {
//         Ok(cipher) => {
//             cipher.encrypt_block(&mut block);
//             cipher.decrypt_block(&mut block);
//             assert_eq!(block, block_copy);
//         }
//         Err(e) => {
//             println!("암호화 키 초기화 중 오류 발생: {:?}", e);
//         }
//     }

// And decrypt it back



// Implementation supports parallel block processing. Number of blocks
// processed in parallel depends in general on hardware capabilities.
// This is achieved by instruction-level parallelism (ILP) on a single
// CPU core, which is differen from multi-threaded parallelism.
//     let mut blocks = [block; 100];
    // cipher.encrypt_blocks(&mut blocks);

    // for block in blocks.iter_mut() {
        // cipher.decrypt_block(block);
        // assert_eq!(block, &block_copy);
    // }

// `decrypt_blocks` also supports parallel block processing.
//     cipher.decrypt_blocks(&mut blocks);

    // for block in blocks.iter_mut() {
        // cipher.encrypt_block(block);
        // assert_eq!(block, &block_copy);
    // }
// }


// fn encrypt_data_aes_ctr(data: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
//     let key = GenericArray::from_slice(key);
//     let nonce = GenericArray::from_slice(iv);
//
//     // AES-128-CTR 암호화 객체 생성
//
//     let mut cipher = ctr::Ctr128BE::<Aes128>::new(key,nonce);
//
//     // 데이터 복사 및 암호화
//     let mut buffer = data.to_vec();
//     cipher.apply_keystream(&mut buffer);
//
//     buffer
// }





// pub fn encrypt_key<P, R, B, S>(
//     dir: P,
//     rng: &mut R,
//     pk: B,
//     password: S,
//     name: Option<&str>,
// ) -> Result<String, KeystoreError>
//     where
//         P: AsRef<Path>,
//         R: Rng + CryptoRng,
//         B: AsRef<[u8]>,
//         S: AsRef<[u8]>,
// {
//     // Generate a random salt.
//     let mut salt = vec![0u8; DEFAULT_KEY_SIZE];
//     rng.fill_bytes(salt.as_mut_slice());
//
//     // Derive the key.
//     let mut key = vec![0u8; DEFAULT_KDF_PARAMS_DKLEN as usize];
//     let scrypt_params = ScryptParams::new(
//         DEFAULT_KDF_PARAMS_LOG_N,
//         DEFAULT_KDF_PARAMS_R,
//         DEFAULT_KDF_PARAMS_P,
//     )?;
//     scrypt(password.as_ref(), &salt, &scrypt_params, key.as_mut_slice())?;
//
//     // Encrypt the private key using AES-128-CTR.
//     let mut iv = vec![0u8; DEFAULT_IV_SIZE];
//     rng.fill_bytes(iv.as_mut_slice());
//
//     let encryptor = Aes128Ctr::new(&key[..16], &iv[..16]).expect("invalid length");
//
//     let mut ciphertext = pk.as_ref().to_vec();
//     encryptor.apply_keystream(&mut ciphertext);
//
//     // Calculate the MAC.
//     let mac = Keccak256::new()
//         .chain(&key[16..32])
//         .chain(&ciphertext)
//         .finalize();
//
//     // If a file name is not specified for the keystore, simply use the strigified uuid.
//     let id = Uuid::new_v4();
//     let name = if let Some(name) = name {
//         name.to_string()
//     } else {
//         id.to_string()
//     };
//
//     // Construct and serialize the encrypted JSON keystore.
//     let keystore = EthKeystore {
//         id,
//         version: 3,
//         crypto: CryptoJson {
//             cipher: String::from(DEFAULT_CIPHER),
//             cipherparams: CipherparamsJson { iv },
//             ciphertext: ciphertext.to_vec(),
//             kdf: KdfType::Scrypt,
//             kdfparams: KdfparamsType::Scrypt {
//                 dklen: DEFAULT_KDF_PARAMS_DKLEN,
//                 n: 2u32.pow(DEFAULT_KDF_PARAMS_LOG_N as u32),
//                 p: DEFAULT_KDF_PARAMS_P,
//                 r: DEFAULT_KDF_PARAMS_R,
//                 salt,
//             },
//             mac: mac.to_vec(),
//         },
//         #[cfg(feature = "geth-compat")]
//         address: address_from_pk(&pk)?,
//     };
//     let contents = serde_json::to_string(&keystore)?;
//
//     // Create a file in write-only mode, to store the encrypted JSON keystore.
//     let mut file = File::create(dir.as_ref().join(&name))?;
//     file.write_all(contents.as_bytes())?;
//
//     Ok(id.to_string())
// }
//
// struct Aes128Ctr {
//     inner: ctr::CtrCore<Aes128, ctr::flavors::Ctr128BE>,
// }
//
// impl Aes128Ctr {
//     fn new(key: &[u8], iv: &[u8]) -> Result<Self, cipher::InvalidLength> {
//         let cipher = aes::Aes128::new_from_slice(key).unwrap();
//         let inner = ctr::CtrCore::inner_iv_slice_init(cipher, iv).unwrap();
//         Ok(Self { inner })
//     }
//
//     fn apply_keystream(self, buf: &mut [u8]) {
//         self.inner.apply_keystream_partial(buf.into());
//     }
// }