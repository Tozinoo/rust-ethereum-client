use std::fs;
use std::io::{self, Read};
use std::path::Path;
use serde_json;
use crate::accounts::keystore::keystores::Keystore;

fn read_file() -> io::Result<Keystore> {
    let mut file = fs::File::open("keystore/UTC--2024-02-15T00-49-43.789818000Z--25f6aab6aa6dacb9768d6558efbd39b4cf54f80e.txt")?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    let keystore:Keystore = serde_json::from_str(&contents).expect("can't deserialize");

    Ok(keystore)
}

pub fn decrypt_keystore_file(path : &Path, password :  ) {
    let contents = read_file();
    match contents {
        Ok(contents) => {println!("read file end {:?}",contents);}
        Err(e) => {}
    }
}