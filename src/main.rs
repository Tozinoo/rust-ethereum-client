use crate::accounts::keystore::keystores::{decrypt_keystore_file, generate_keystore};
use std::path::Path;

mod accounts;
mod types;
mod constants;

fn main() {
     // let _ = generate_keystore();
     let path_str = "keystore/UTC--2024-02-16T05-26-08.370791000Z--ec5e47aab8803071f42c0ef024e472ca198728e4.txt";
     let path = Path::new(path_str);
     let _ = decrypt_keystore_file(path);
}

// scrypt 62cf39ccb0fd2393afc8c127c375e4d03d1478e4451951ccd6e404d3fdc4bbef
// pk     6a4f5c11dd96143ff7bcfc98d3953f1d57dd53cc6950602f6db8b5bb0ec6b832

// scrypt 93bc6e54eb9ca9903facad7bcefb135cc38f8389cf740597a01014ed1df3780c


// 50c9e1729d58b779fabe8666ab1619a3ec3ad05b6988d4c5e1d3f4cd7b1b274b
// d63725c939f41aaf520c024661a8357ca488ad1d1c55c335f6448d85eab1e8a055f0b62eec10eef3352ba22ed93b9286be16be28fb65473acde16e912b168418