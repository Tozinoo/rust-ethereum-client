use std::io::{self, Write};
use serde_json;
use rust_ethereum_client::types::{PrivateKey, PublicKey};


pub fn generate_keystore(private_key: PrivateKey, password: String) -> std::io::Result<()> {
    Ok(())
}

fn input_password() -> String {
    print!("Please enter any key to generate a private key : "); //
    io::stdout().flush().expect("Failed to flush stdout."); //

    let mut password = String::new();

    io::stdin()
        .read_line(&mut password)
        .expect("입력을 읽는 데 실패했습니다.");

    password
}