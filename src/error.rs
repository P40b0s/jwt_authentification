use thiserror::Error;

#[derive(Error, Debug)]
pub enum JwtError
{
    #[error(transparent)]
    JWTError(#[from] jsonwebtoken::errors::Error),
    #[error("Ошибка валидации токена доступа `{0}`")]
    JWTValidateError(String),
}

impl serde::Serialize for JwtError 
{
  fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
  where
  S: serde::ser::Serializer,
  {
    serializer.serialize_str(self.to_string().as_ref())
  }
}