use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey};
use ring::signature::{Ed25519KeyPair, KeyPair};

use crate::JWT;

fn gen_pkc8()
{
    let doc = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap();
    std::fs::write("key.pkcs8", doc.as_ref()).unwrap();
}
fn load_pkc8() -> JWT
{
    let pkcs8 = utilites::io::read_file_to_binary("key.pkcs8").unwrap();
    let pair = Ed25519KeyPair::from_pkcs8(&pkcs8).unwrap();
    let encoding_key = EncodingKey::from_ed_der(&pkcs8);
    let public_key = pair.public_key().as_ref();
    let decoding_key = DecodingKey::from_ed_der(pair.public_key().as_ref());
    let jwt = JWT
        { 
            encoding_key,
            decoding_key,
            public_key: public_key.to_vec(),
            algo: Algorithm::EdDSA,
        };
        jwt
}
#[cfg(test)]
mod tests
{
    #[test]
    fn test_gen()
    {
        super::gen_pkc8();
        
    }
    #[test]
    fn test_load_key()
    {
        let _ = logger::StructLogger::new_default();
        let id = "1234".to_owned();
        let role = "Operator"; 
        let mut key = super::load_pkc8();
      
    }
}