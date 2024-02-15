use crate::accounts::keystore::decrypt_keystore::decrypt_keystore_file;
use crate::accounts::keystore::keystores::generate_keystore;

mod accounts;
mod types;
mod constants;

fn main() {
    let _ = generate_keystore();
    let _ = decrypt_keystore_file();
}
