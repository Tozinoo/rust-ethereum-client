use crate::accounts::keystore::keystores::generate_keystore;

mod accounts;
mod types;
mod constants;

fn main() {
    let _ = generate_keystore();
}
