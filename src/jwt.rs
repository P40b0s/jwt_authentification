use std::{collections::HashSet, path::Path};

use jsonwebtoken::
{
    decode, encode, errors::{Error, ErrorKind}, get_current_timestamp, Algorithm, DecodingKey, EncodingKey, Validation
};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};
use crate::error::AuthError;
pub use jsonwebtoken::TokenData;
pub struct JWT
{
    pub (crate) encoding_key: EncodingKey,
    pub (crate) decoding_key: DecodingKey,
    pub (crate) public_key: Vec<u8>,
    pub (crate) algo: Algorithm
}

impl JWT
{
    ///create new instance with key in memory, can validate keys only created in this session
    pub fn new_in_memory() -> Self
    {
        let doc = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap();
        let encoding_key = EncodingKey::from_ed_der(doc.as_ref());
        let pair = Ed25519KeyPair::from_pkcs8(doc.as_ref()).unwrap();
        let public_key = pair.public_key().as_ref();
        let decoding_key = DecodingKey::from_ed_der(pair.public_key().as_ref());
        JWT
        { 
            encoding_key,
            decoding_key,
            public_key: public_key.to_vec(),
            algo: Algorithm::EdDSA,
        }
    }
    ///if not exixsts, create new key file pkcs8 and create new JWT instance with him
    pub fn new_in_file<P: AsRef<Path>>(path: P) -> Self
    {
        if std::fs::exists(path.as_ref()).is_ok_and(|a| a == false)
        {
            let doc = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap();
            std::fs::write(path.as_ref(), doc.as_ref()).unwrap();
        }
        let pkcs8 = utilites::io::read_file_to_binary(path).unwrap();
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
    ///token lifetime in minutes
    pub fn new_access<I: AsRef<str>, R>(&self, user_id: I, role: R, lifitime: i64) -> String
    where R: for<'de> Deserialize<'de> + Serialize + PartialEq + Clone
    {
        let iat =  OffsetDateTime::now_utc();
        let exp = iat + Duration::minutes(lifitime);
        let claims = Claims { sub: user_id.as_ref().to_owned(),  exp, aud: None,  iat, role};
        encode(&jsonwebtoken::Header::new(self.algo.clone()), &claims, &self.encoding_key).unwrap()
    }
    ///token lifetime in minutes
    pub fn new_access_with_audience<I: AsRef<str>, R, A: ToString>(&self, user_id: I, role: R, audience: &[A], lifitime: i64) -> String
    where R: for<'de> Deserialize<'de> + Serialize + PartialEq + Clone
    {
        let iat =  OffsetDateTime::now_utc();
        let exp = iat + Duration::minutes(lifitime);
        let claims = Claims { sub: user_id.as_ref().to_owned(),  exp, aud: Some(audience.iter().map(|m| m.to_string()).collect()),  iat, role};
        encode(&jsonwebtoken::Header::new(self.algo.clone()), &claims, &self.encoding_key).unwrap()
    }

    pub fn validate_access<R, I: AsRef<str>>(&self, token: I, user_id: I) -> Result<TokenData<Claims<R>>, AuthError>
    where R: for<'de> Deserialize<'de> + Serialize + PartialEq + Clone
    {
        let mut validation = Validation::new(self.algo.clone());
        validation.aud = None;
        validation.sub = Some(user_id.as_ref().to_owned());
        //by default = 60 + 60 secs to key expired date
        validation.leeway = 0;
        self.validate(token, validation)
    }
    pub fn validate_access_with_audience<R, I: AsRef<str>, A: ToString>(&self, token: I, user_id: I, audience: &[A]) -> Result<TokenData<Claims<R>>, AuthError>
    where R: for<'de> Deserialize<'de> + Serialize + PartialEq + Clone
    {
        let mut validation = Validation::new(self.algo.clone());
        validation.sub = Some(user_id.as_ref().to_owned());
        validation.set_audience(audience);
        validation.leeway = 0;
        self.validate(token, validation)
    }

    fn validate<R, I: AsRef<str>>(&self, token: I, validation: Validation) -> Result<TokenData<Claims<R>>, AuthError>
    where R: for<'de> Deserialize<'de> + Serialize + PartialEq + Clone
    {
        let token_data = match decode::<Claims<R>>(token.as_ref(), &self.decoding_key, &validation) 
        {
            Ok(c) => Ok(c),
            Err(err) => match *err.kind() 
            {
                ErrorKind::InvalidToken => 
                {
                    logger::error!("Текущий токен не валиден");
                    Err(AuthError::JWTValidateError("Текущий токен не валиден".to_owned()))
                },
                ErrorKind::InvalidIssuer =>  
                {
                    logger::error!("Issuer is invalid");
                    Err(AuthError::JWTValidateError("iss не совпадает с валидируемым".to_owned()))
                },
                ErrorKind::InvalidSubject =>
                {
                    logger::error!("Subject is invalid");
                    Err(AuthError::JWTValidateError("sub не совпадает с валидируемым".to_owned()))
                },
                ErrorKind::InvalidAudience =>
                {
                    logger::error!("Audience is invalid");
                    Err(AuthError::JWTValidateError("audience не совпадает с валидируемым".to_owned()))
                },
                ErrorKind::ExpiredSignature => 
                {
                    logger::error!("Token is expired");
                    Err(AuthError::JWTValidateError("время жизни токена истекло".to_owned()))
                }
                _ => Err(AuthError::JWTError(err))
            },
        };
        let claims = token_data?;
        Ok(claims)
    }

   

    pub fn get_public_key(&self) -> String
    {
        utilites::Hasher::from_bytes_to_base64(&self.public_key)
    }
}


#[derive(Debug, Serialize, Deserialize)]
pub struct Claims<R>
{
    sub: String,
    #[serde(with = "jwt_numeric_date")]
    exp: OffsetDateTime,
    #[serde(with = "jwt_numeric_date")]
    iat: OffsetDateTime,
    role: R,
    aud: Option<HashSet<String>>
}
impl<R> Claims<R> where R: for<'de> Deserialize<'de> + Serialize + PartialEq
{
    pub fn user_id(&self) -> &str
    {
        &self.sub
    }
    pub fn role(&self) -> &R
    {
        &self.role
    }
}

mod jwt_numeric_date 
{
    use serde::{self, Deserialize, Deserializer, Serializer};
    use time::OffsetDateTime;

    pub fn serialize<S>(date: &OffsetDateTime, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let timestamp = date.unix_timestamp();
        serializer.serialize_i64(timestamp)
    }
    pub fn deserialize<'de, D>(deserializer: D) -> Result<OffsetDateTime, D::Error>
    where
        D: Deserializer<'de>,
    {
        OffsetDateTime::from_unix_timestamp(i64::deserialize(deserializer)?)
            .map_err(|_| serde::de::Error::custom("invalid Unix timestamp value"))
    }
}

#[cfg(test)]
mod tests
{
    #[tokio::test]
    async fn gen_key()
    {
        let _ = logger::StructLogger::new_default();
        let mut jwt  = super::JWT::new_in_file("key.pkcs8");
        let id = "1234".to_owned();
        let id_for_check = "4321".to_owned();
        let role = "Operator";
        let aud = ["www.ya.ru", "www.yandex.ru"];
        let aud_check = ["www.yandex.ru"];
        let key = jwt.new_access(&id, role.to_owned(), 5);
        logger::info!("access: {}",  key);
        let upd = jwt.new_access(&id, role.to_owned(), 5);
        let va = jwt.validate_access::<String, _>(&upd, &id).unwrap();
        logger::info!(" upd_access: {} user_id: {} role: {}", &upd, va.claims.user_id(), va.claims.role());
        let upd2 = jwt.new_access_with_audience(&id, role.to_owned(), &aud, 5);
        let claims: jsonwebtoken::TokenData<crate::Claims<String>> = jwt.validate_access_with_audience(&upd2, &id, &aud_check).unwrap();
        logger::info!("upd2_claims: {:?}", claims);
    }
    #[tokio::test]
    async fn test_generated()
    {
        let token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9.eyJzdWIiOiIxMjM0IiwiZXhwIjoxNzQxNzkwNjc2LCJpYXQiOjE3NDE3OTAzNzYsInJvbGUiOiJPcGVyYXRvciIsImF1ZCI6bnVsbH0.hKIYSkAYCyIKukBlbeMF6zvRFRuHsIZiKr-0XpTJXlzLHkTqta3hkA3Yp1NIMVAvey46zoCBw0Fn5S61naq2DQ";
        let id = "1234";
        let role = "Operator";
        let _ = logger::StructLogger::new_default();
        let mut jwt  = super::JWT::new_in_file("key.pkcs8");
        let claims = jwt.validate_access::<String, _>(token, id);
        logger::info!("claims: {:?}", claims);

        //eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9.eyJzdWIiOiIxMjM0IiwiZXhwIjoxNzQxNzkwNjc2LCJpYXQiOjE3NDE3OTAzNzYsInJvbGUiOiJPcGVyYXRvciIsImF1ZCI6bnVsbH0.hKIYSkAYCyIKukBlbeMF6zvRFRuHsIZiKr-0XpTJXlzLHkTqta3hkA3Yp1NIMVAvey46zoCBw0Fn5S61naq2DQ
        //eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9.eyJzdWIiOiIxMjM0IiwiZXhwIjoxNzQxNzkwNjc2LCJpYXQiOjE3NDE3OTAzNzYsInJvbGUiOiJPcGVyYXRvciIsImF1ZCI6bnVsbH0.hKIYSkAYCyIKukBlbeMF6zvRFRuHsIZiKr-0XpTJXlzLHkTqta3hkA3Yp1NIMVAvey46zoCBw0Fn5S61naq2DQ
        //eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9.eyJzdWIiOiIxMjM0IiwiZXhwIjoxNzQxNzkwNzc5LCJpYXQiOjE3NDE3OTA0NzksInJvbGUiOiJPcGVyYXRvciIsImF1ZCI6bnVsbH0.FZ7nN6ywCGRw-3n_Wu6IMnTAK9Crz73Nb22fSX7UvZM1UT_bjIGbtp2dlqbKzV7bmghV6L3wlT9iS8ec4WadDg
    }
}