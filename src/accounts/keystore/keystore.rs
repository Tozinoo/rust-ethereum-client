use std::io::{self, Write};
use std::fs::File;
use chrono::Utc;
use hex::encode;

use secp256k1::{Secp256k1};
use keccak_hash::{H256, keccak};
// use crate::constants::{PRIVATE_KEY_SIZE, PUBLIC_KEY_SIZE};
use serde::{Serialize, Deserialize};
use serde_json;

#[derive(Serialize, Deserialize)]
struct Keystore {
    private_key: String,
    public_key: String,
    address: String,
}

pub const PRIVATE_KEY_SIZE: usize = 32;
/// The size (in bytes) of a public key.
pub const PUBLIC_KEY_SIZE: usize = 20;


//type
type PrivateKey = [u8; PRIVATE_KEY_SIZE];
type PublicKey = [u8; PUBLIC_KEY_SIZE];

extern crate secp256k1;

// pub fn generate_key() {
//     // generate_private_key()
// }

/// pub struct SecretKey([u8; constants::SECRET_KEY_SIZE]);
/// SECRET_KEY_SIZE: usize = 32;
pub fn generate_key() -> (PrivateKey, PublicKey) {
    let secp = Secp256k1::new();
    let (secret_key, public_key) = secp.generate_keypair(&mut rand::thread_rng());

    // publc key
    let serialized_public_key = public_key.serialize_uncompressed();
    let mut serialized_public_key_without_prefix: [u8; 64] = [0; 64];
    serialized_public_key_without_prefix.copy_from_slice(&serialized_public_key[1..65]);
    let public_key = keccak(serialized_public_key_without_prefix);

    (secret_key.secret_bytes(), slice_last_20_bytes(public_key))
}

fn slice_last_20_bytes(public_key: H256) -> PublicKey {
    let public_key_bytes = public_key.as_bytes();
    let last_20_bytes: PublicKey = public_key_bytes[12..32].try_into().expect("Slice with incorrect length");
    last_20_bytes
}

pub fn save_keystore(private_key: PrivateKey, address: PublicKey) -> std::io::Result<()> {
    let keystore = Keystore {
        private_key: hex::encode(private_key),
        public_key: hex::encode(address),
        address: format!("0x{}", hex::encode(address)),
    };

    let keystore_json = serde_json::to_string_pretty(&keystore)?;
    println!("{}",keystore_json);
    let mut file = File::create("./keystore/keystore.json")?;
    file.write_all(keystore_json.as_bytes())?;

    Ok(())
}



pub fn make_file(public_key: PublicKey) -> std::io::Result<()> {
    // 현재 UTC 시간을 가져옵니다.
    let now = Utc::now();
    // 파일명을 위해 시간을 포맷합니다. 예: "2023-01-30T15-00-00Z"
    let file_name = now.format("%Y-%m-%dT%H-%M-%SZ").to_string();

    // 파일을 생성합니다. 여기서는 파일명에 UTC 시간을 사용합니다.
    let mut file = File::create(file_name + "-" + hex::encode(public_key).as_str()+ ".txt")?;

    // 파일에 내용을 씁니다. 실제 사용 시 필요한 내용으로 대체하세요.
    file.write_all(b"Hello, world!")?;

    Ok(())
}



    // 0x4b9cd2a93926df1a9d70682bf3da9e06c33ea1bb1e8929877600d790c8fed79c
    // 0x230AbdD712caf39D71132a62c8FA85A50C16Fc53
    // let pub_key: [u8;65] =  [4, 21, 167, 239, 137, 58, 100, 122, 131, 120, 195, 246, 39, 211, 211, 239, 58, 241, 225, 104, 205, 205, 162, 187, 208, 69, 231, 80, 7, 172, 238, 78, 219, 74, 0, 141, 92, 15, 146, 82, 82, 223, 52, 52, 5, 196, 187, 90, 159, 249, 155, 216, 212, 74, 245, 106, 205, 146, 226, 216, 73, 120, 248, 135, 82];
    // println!("공개 키 원본: {:?}", pub_key);
    // println!("공개 키 바이트화: {:?}", secret_key_to_hex_str(&pub_key));
    // println!("공개 키 keccak: {:?}", secret_key_to_hex_str(&pub_key));
    // assert!(slice_public_key()=="0x230AbdD712caf39D71132a62c8FA85A50C16Fc53", "public key가 안맞누");
    // let secret_key_bytes_vec = secret_key.secret_bytes();

    // let mut public_key_bytes = public_key.serialize_uncompressed();

    // println!("공개 키1: {:?}", public_key_bytes);
    // let public_key = keccak256(&mut public_key_bytes);
    // println!("공개 키2: {:?}", public_key_bytes);
    // // let pubkey = keccak256(&mut public_key_bytes);
    // // secret_key_bytes_vec
    // println!("개인 키1: {:?}", secret_key);
    // println!("개인 키2: {:?}", secret_key_bytes_vec);
    // println!("개인 키3: {:?}", secret_key_to_hex_str(&secret_key_bytes_vec));
    // println!("공개 키3: {:?}", slice_public_key(&public_key_bytes));
    // println!("공개 키4: {:?}", secret_key_to_hex_str(&public_key_bytes));
    // secret_key_to_hex_str(&secret_key_bytes_vec)






// pub fn secret_key_to_hex_str(secret_key_bytes: [u8; 32]) -> String {
//     let mut hex_secret_key = String::new();
//     for secret_key_byte in secret_key_bytes {
//         hex_secret_key.push_str(&format!("{:02x}",secret_key_byte));
//     }
//     format!("0x{}", hex_secret_key)
// }

// pub fn u8_to_hex_str(secret_key_bytes: [u8; 32]) -> String {
//     let mut hex_secret_key = String::new();
//     for secret_key_byte in secret_key_bytes {
//         hex_secret_key.push_str(&format!("{:02x}",secret_key_byte));
//     }
//     format!("0x{}", hex_secret_key)
// }
//


// 0xb3c0e684210b90cb834e7d93811e2cd993acc48cb9ff0d44a4a895b8325753b0
// [179, 192, 230, 132, 33, 11, 144, 203, 131, 78, 125, 147, 129, 30, 44, 217, 147, 172, 196, 140, 185, 255, 13, 68, 164, 168, 149, 184, 50, 87, 83, 176]
//  [167, 95, 188, 228, 230, 190, 252, 52, 202, 242, 29, 137, 217, 126, 132, 37, 23, 153, 155, 170, 23, 100, 129, 244, 211, 53, 152, 219, 241, 73, 3, 16, 33, 35, 8, 220, 184, 105, 142, 65, 220, 161, 43, 20, 139, 99, 76, 23
// 7, 251, 115, 91, 3, 131, 5, 99, 138, 214, 100, 112, 185, 230, 209, 229, 90, 237]

// fn generate_public_key() {
//     let pub_key: [u8;65] =  [4, 21, 167, 239, 137, 58, 100, 122, 131, 120, 195, 246, 39, 211, 211, 239, 58, 241, 225, 104, 205, 205, 162, 187, 208, 69, 231, 80, 7, 172, 238, 78, 219, 74, 0, 141, 92, 15, 146, 82, 82, 223, 52, 52, 5, 196, 187, 90, 159, 249, 155, 216, 212, 74, 245, 106, 205, 146, 226, 216, 73, 120, 248, 135, 82];
//     let mut pub_key_without_first_byte: Vec<u8> = pub_key[1..].to_vec();
//     println!("공개 키 원본: {:?}", pub_key);
//     println!("공개 키 바이트화: {:?}", secret_key_to_hex_str(&pub_key));
//     let mut pub_key_bytes = pub_key_without_first_byte.as_mut_slice();
//     let pub_key_without_first_byte = &pub_key[1..];
//     let a = keccak(&pub_key_without_first_byte);
//     let pubkey_hash = keccak256(pub_key_bytes);
//     let a_bytes = a.as_bytes();
//
//     let last_20_bytes = &a_bytes[12..];
//     println!("공개 키 keccak: {:?}", last_20_bytes);
// }

pub fn input_password() {
    print!("Please enter any key to generate a private key : "); //
    io::stdout().flush().expect("Failed to flush stdout."); //

    let mut password = String::new();

    io::stdin()
        .read_line(&mut password)
        .expect("입력을 읽는 데 실패했습니다.");

    println!("안녕하세요, {}!", password.trim());
}