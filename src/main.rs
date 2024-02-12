use crate::accounts::generate_key::generate_key;
use hex::encode;
use crate::accounts::keystore::keystores::generate_keystore;

mod accounts;
mod types;
mod constants;

fn main() {
    // accounts::keystore::keystore::input_password();
    let (secret, public) = generate_key();
    let a = encode(secret);
    let b = encode(public);
    generate_keystore(secret,public,String::from("asdf"));
    println!("0x{:?}",a);
    println!("0x{:?}",b);
}

// func GenerateKey(c elliptic.Curve, rand io.Reader) (*PrivateKey, error) {
// if boring.Enabled && rand == boring.RandReader {
// x, y, d, err := boring.GenerateKeyECDSA(c.Params().Name)
// if err != nil {
// return nil, err
// }
// return &PrivateKey{PublicKey: PublicKey{Curve: c, X: bbig.Dec(x), Y: bbig.Dec(y)}, D: bbig.Dec(d)}, nil
// }
// boring.UnreachableExceptTests()
//
// k, err := randFieldElement(c, rand)
// if err != nil {
// return nil, err
// }
//
// priv := new(PrivateKey)
// priv.PublicKey.Curve = c
// priv.D = k
// priv.PublicKey.X, priv.PublicKey.Y = c.ScalarBaseMult(k.Bytes())
// return priv, nil
// }