use std::io::{self, Write}; // Write 트레잇을 사용하기 위해 추가합니다.
extern crate secp256k1;
use secp256k1::{Secp256k1, SecretKey};

pub fn generate_key() {
    let secp = Secp256k1::new();

    // 무작위 개인 키 생성
    let (secret_key, public_key) = secp.generate_keypair(&mut rand::thread_rng());

    println!("개인 키: {:?}", secret_key);
    println!("공개 키: {:?}", public_key);

}


pub fn input_key() {
    print!("Please enter any key to generate a private key : "); //
    io::stdout().flush().expect("Failed to flush stdout."); // 출력 버퍼를 비워서 메시지가 즉시 표시되도록 합니다.

    let mut password = String::new();

    io::stdin()
        .read_line(&mut password)
        .expect("입력을 읽는 데 실패했습니다.");

    println!("안녕하세요, {}!", password.trim());
}

