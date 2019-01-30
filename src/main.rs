extern crate num_bigint;

use num_bigint::BigInt;

fn secure_prime_generator() -> (BigInt, BigInt) {
    let p = BigInt::parse_bytes(b"251352642263889039868309043894037481379002996715589396370854987834622532561522720403074015628816522584866374785754812790090831773387112312703220610291993961566100333483106513061700679351674883108504663868999773335993131871433147375498526830250690800432950741107471775936506033522777378528889986463928680062779", 10).unwrap();
    let q = BigInt::parse_bytes(b"234601306906702217804957533486106543816960131695391266497422573355527800260716665381597389816091857137372406177664905766000014102540204528163683625043444669386812465309478832002368041295429725611772236019022712629169757194963880836723186721316763532024657471001347998077008043814690024358601642733925216784203", 10).unwrap();
    (p, q)
}

fn modinv(mut x: BigInt, mut y: BigInt) -> BigInt {
    let (mut r, mut s) = (BigInt::from(1i32), BigInt::from(0i32));
    let zero = BigInt::from(0i32);
    while y > zero {
        let tmp_s = s.clone();
        s = &r - &x / &y * &s;
        r = tmp_s;
        let tmp_y = y.clone();
        y = &x % &y;
        x = tmp_y;
    }
    r
}

fn rsa_generate_keys() -> ((BigInt, BigInt), (BigInt, BigInt)) {
    let (p, q) = secure_prime_generator();
    let n = &p * &q;
    let t = &n - &p - &q + &BigInt::from(1u32);
    let e = BigInt::from(65537i32);
    let zero = BigInt::from(0i32);
    let mut d = modinv(e.clone(), t.clone())%&t;
    if d < zero{
        d += &t
    }
    assert_eq!((&d * &e) % t, BigInt::from(1i32));
    ((e, n.clone()), (d, n.clone()))
}

fn rsa(plaintext: &BigInt, public_key: &(BigInt, BigInt)) -> BigInt {
    plaintext.modpow(&public_key.0, &public_key.1)
}

fn main() {
    let plan_text = BigInt::from(4207599127i64);
    let (public_key, secret_key) = rsa_generate_keys();
    let cipher_text = rsa(&plan_text, &public_key);
    assert_eq!(plan_text,  rsa(&cipher_text, &secret_key));
}
