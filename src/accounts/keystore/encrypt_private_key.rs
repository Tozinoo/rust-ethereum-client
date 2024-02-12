use std::io::{self, Write};
use scrypt::{
    password_hash::{PasswordHasher, SaltString},
    Scrypt,
};
use aes::Aes128;
use ctr::cipher::{ StreamCipher, generic_array::GenericArray};
use hex::encode;


use crate::types::types::{PrivateKey};

pub fn encrypt_key(private_key: PrivateKey, password: String) {

}

pub fn scrypt_password() -> Result<(), Box<dyn std::error::Error>> {
    let password = input_password();
    let salt = SaltString::generate(&mut rand::thread_rng());
    let password_hash = Scrypt.hash_password(password.as_bytes(), &salt)?;
    println!("Hashed password: {:?}", password_hash);

    Ok(())
}

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


fn input_password() -> String {
    print!("Please enter any key to generate a private key : "); //
    io::stdout().flush().expect("Failed to flush stdout."); //

    let mut password = String::new();

    io::stdin()
        .read_line(&mut password)
        .expect("Failed to read input....");

    password
}


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