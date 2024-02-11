use crate::accounts::keystore::keystore::{generate_key, make_file};
use hex::encode;

mod accounts; // account 모듈을 선언합니다.


fn main() {
    // accounts::keystore::keystore::input_password();
    let (secret, public) = generate_key();
    let SecretKey = encode(secret);
    let PublicKey = encode(public);
    println!("0x{:?}",SecretKey);
    println!("0x{:?}",PublicKey);
    make_file(public);

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