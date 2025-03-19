use std::{collections::HashSet, path::Path};
use jsonwebtoken::
{
    decode, encode, errors::ErrorKind, Algorithm, DecodingKey, EncodingKey, Validation
};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};
use crate::error::JwtError;
pub use jsonwebtoken::TokenData;
pub struct JWT
{
    pub (crate) encoding_key: EncodingKey,
    pub (crate) decoding_key: DecodingKey,
    pub (crate) public_key: Vec<u8>,
    pub (crate) algo: Algorithm,
    pub (crate) claims: Option<Claims>
}

pub struct Validator<'a>
{
    validation: Validation,
    roles: Option<&'a[&'a str]>,
    jwt: &'a JWT,
}
impl<'a> Validator<'a>
{
    fn new(jwt: &'a JWT) -> Self
    {
        let validation = Validation::new(jwt.algo.clone());
        Self
        {
            validation,
            roles: None,
            jwt,
        }
    }
    pub fn with_subject<T: ToString>(mut self, id: T) -> Self
    {
        self.validation.sub = Some(id.to_string());
        self.validation.leeway = 0;
        self
    }
    pub fn with_audience<T: ToString>(mut self, aud: &[T]) -> Self
    {
        if !aud.is_empty()
        {
            self.validation.set_audience(aud);
        }
        self
    }
    pub fn with_roles(mut self, roles: &'a [&'a str]) -> Self
    {
        if !roles.is_empty()
        {
            self.roles = Some(roles);
        }
        self
    }
    pub fn validate<T: AsRef<str>>(&self, token: T) -> Result<TokenData<Claims>, JwtError>
    {
        let token_data = match decode::<Claims>(token.as_ref(), &self.jwt.decoding_key, &self.validation) 
        {
            Ok(c) => Ok(c),
            Err(err) => match *err.kind() 
            {
                ErrorKind::InvalidToken => 
                {
                    logger::error!("Token is invalid");
                    Err(JwtError::JWTValidateError("Token is invalid".to_owned()))
                },
                ErrorKind::InvalidIssuer =>  
                {
                    logger::error!("Issuer is invalid");
                    Err(JwtError::JWTValidateError("Issuer is invalid".to_owned()))
                },
                ErrorKind::InvalidSubject =>
                {
                    logger::error!("Subject is invalid");
                    Err(JwtError::JWTValidateError("Subject is invalid".to_owned()))
                },
                ErrorKind::InvalidAudience =>
                {
                    logger::error!("Audience is invalid");
                    Err(JwtError::JWTValidateError("Audience is invalid".to_owned()))
                },
                ErrorKind::ExpiredSignature => 
                {
                    logger::error!("Token is expired");
                    Err(JwtError::JWTValidateError("Token is expired".to_owned()))
                },
                ErrorKind::InvalidSignature =>
                {
                    logger::error!("Token have invalid signature");
                    Err(JwtError::JWTValidateError("Token have invalid signature".to_owned()))
                },
                _ => Err(JwtError::JWTError(err))
            },
        };
        let claims = token_data?;
        if let Some(roles) = self.roles
        {
            if let Some(claims_role) = claims.claims.role()
            {
                if !roles.contains(&claims_role.as_str())
                {
                    logger::error!("Role is invalid");
                    return Err(JwtError::JWTValidateError("role is invalid".to_owned()));
                }
            }
        }
        Ok(claims)
    }
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
            claims: None
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
                claims: None
            };
            jwt
    }
    ///by default lifetime is 5 minutes, we can update exp date in `gen_key`
    pub fn new_access<T: ToString>(&mut self, user_id: T) -> &mut Self
    {
        let iat =  OffsetDateTime::now_utc();
        let exp = iat + Duration::minutes(5);
        let claims = Claims { sub: user_id.to_string(), exp, aud: None,  iat, role: None};
        self.claims = Some(claims);
        self
    }
    pub fn with_role<T: ToString>(&mut self, role: T) -> &mut Self
    {
        if let Some(claims) = self.claims.as_mut()
        {
            claims.role = Some(role.to_string());
        }
        self
    }
    pub fn with_audience<T: ToString>(&mut self, audience: &[T]) -> &mut Self
    {
        if !audience.is_empty()
        {
            if let Some(claims) = self.claims.as_mut()
            {
                claims.aud = Some(audience.iter().map(|m| m.to_string()).collect());
            }
        }
        self
    }
    pub fn gen_key(&mut self, lifetime: i64) -> String
    {
        if let Some(claims) = self.claims.as_mut()
        {
            let iat =  OffsetDateTime::now_utc();
            let exp = iat + Duration::minutes(lifetime);
            claims.exp = exp;
            claims.iat = iat;
            encode(&jsonwebtoken::Header::new(self.algo.clone()), claims, &self.encoding_key).unwrap()
        }
        else 
        {
            String::new()    
        }
    }
    
    pub fn validator(&self) -> Validator
    {
        Validator::new(&self)
    }

    pub fn get_public_key(&self) -> String
    {
        utilites::Hasher::from_bytes_to_base64(&self.public_key)
    }
}


#[derive(Debug, Serialize, Deserialize)]
pub struct Claims
{
    sub: String,
    #[serde(with = "jwt_numeric_date")]
    exp: OffsetDateTime,
    #[serde(with = "jwt_numeric_date")]
    iat: OffsetDateTime,
    role: Option<String>,
    aud: Option<HashSet<String>>
}
impl Claims
{
    pub fn user_id(&self) -> &str
    {
        &self.sub
    }
    pub fn role(&self) -> Option<&String>
    {
        self.role.as_ref()
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
    use std::time::Duration;

    #[test]
    fn test_validation_all()
    {
        let _ = logger::StructLogger::new_default();
        let mut jwt  = super::JWT::new_in_file("key.pkcs8");
        let id = "1234".to_owned();
        let role = "Operator".to_string();
        let aud = ["www.ya.ru", "www.yandex.ru"];
        let aud_check = ["www.yandex.ru"];
        let generator = jwt.new_access(&id)
        .with_role(&role)
        .with_audience(&aud);
        let key = generator.gen_key(5);
        let valid = jwt.validator()
        .with_audience(&aud_check)
        .with_subject(&id)
        .with_roles(&[role.as_str()])
        .validate(&key);
        assert!(valid.is_ok());
    }
    #[test]
    fn test_validation_sub()
    {
        let _ = logger::StructLogger::new_default();
        let mut jwt  = super::JWT::new_in_file("key.pkcs8");
        let id = "1234".to_owned();
        let key = jwt.new_access(&id).gen_key(5);
        let validator = jwt.validator()
        .with_subject(&id)
        .validate(&key);
        assert!(validator.is_ok());
    }
    #[test]
    fn test_validation_role()
    {
        let _ = logger::StructLogger::new_default();
        let mut jwt  = super::JWT::new_in_file("key.pkcs8");
        let id = "1234".to_owned();
        let role = "Operator".to_string();
        let key = jwt.new_access(&id)
        .with_role(&role)
        .gen_key(5);
        let validator = jwt.validator()
        .with_subject(&id)
        .with_roles(&[role.as_str()])
        .validate(&key);
        assert!(validator.is_ok());
    }
    #[test]
    fn test_validation_audience()
    {
        let _ = logger::StructLogger::new_default();
        let mut jwt  = super::JWT::new_in_file("key.pkcs8");
        let id = "1234".to_owned();
        let aud = ["www.ya.ru", "www.yandex.ru"];
        let aud_check = ["www.yandex.ru"];
        let key = jwt.new_access(&id)
        .with_audience(&aud)
        .gen_key(5);
        let validator = jwt.validator()
        .with_audience(&aud_check)
        .validate(&key);
        assert!(validator.is_ok());
    }

    #[test]
    fn test_validation_time_exp()
    {
        let _ = logger::StructLogger::new_default();
        let mut jwt  = super::JWT::new_in_file("key.pkcs8");
        let id = "1234".to_owned();
        let key = jwt.new_access(&id)
        .gen_key(1);
        let validator = jwt.validator()
        .with_subject(&id)
        .validate(&key);
        assert!(validator.is_ok());
        std::thread::sleep(Duration::from_millis(62000));
        let validator = jwt.validator()
        .with_subject(&id)
        .validate(&key);
        assert!(validator.is_err())
    }
    #[test]
    fn test_exp()
    {
        let token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9.eyJzdWIiOiIxMjM0IiwiZXhwIjoxNzQxNzkwNjc2LCJpYXQiOjE3NDE3OTAzNzYsInJvbGUiOiJPcGVyYXRvciIsImF1ZCI6bnVsbH0.hKIYSkAYCyIKukBlbeMF6zvRFRuHsIZiKr-0XpTJXlzLHkTqta3hkA3Yp1NIMVAvey46zoCBw0Fn5S61naq2DQ";
        let id = "1234";
        let role = "Operator";
        let _ = logger::StructLogger::new_default();
        let jwt  = super::JWT::new_in_file("key.pkcs8");
        let claims = jwt.validator().with_subject(id).with_roles(&[role]).validate(token);
        logger::info!("claims: {:?}", claims);
        let err =claims.err().unwrap();
        assert_eq!(err.to_string(), "Ошибка валидации токена доступа `Token is expired`".to_owned());

        //eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9.eyJzdWIiOiIxMjM0IiwiZXhwIjoxNzQxNzkwNjc2LCJpYXQiOjE3NDE3OTAzNzYsInJvbGUiOiJPcGVyYXRvciIsImF1ZCI6bnVsbH0.hKIYSkAYCyIKukBlbeMF6zvRFRuHsIZiKr-0XpTJXlzLHkTqta3hkA3Yp1NIMVAvey46zoCBw0Fn5S61naq2DQ
        //eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9.eyJzdWIiOiIxMjM0IiwiZXhwIjoxNzQxNzkwNjc2LCJpYXQiOjE3NDE3OTAzNzYsInJvbGUiOiJPcGVyYXRvciIsImF1ZCI6bnVsbH0.hKIYSkAYCyIKukBlbeMF6zvRFRuHsIZiKr-0XpTJXlzLHkTqta3hkA3Yp1NIMVAvey46zoCBw0Fn5S61naq2DQ
        //eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9.eyJzdWIiOiIxMjM0IiwiZXhwIjoxNzQxNzkwNzc5LCJpYXQiOjE3NDE3OTA0NzksInJvbGUiOiJPcGVyYXRvciIsImF1ZCI6bnVsbH0.FZ7nN6ywCGRw-3n_Wu6IMnTAK9Crz73Nb22fSX7UvZM1UT_bjIGbtp2dlqbKzV7bmghV6L3wlT9iS8ec4WadDg
    }
}