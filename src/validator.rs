use jsonwebtoken::{decode, errors::ErrorKind, TokenData, Validation};
use crate::{error::JwtError, Claims, JWT};

pub struct Validator<'a>
{
    validation: Validation,
    roles: Option<&'a[&'a str]>,
    jwt: &'a JWT,
}
impl<'a> Validator<'a>
{
    pub (crate) fn new(jwt: &'a JWT) -> Self
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