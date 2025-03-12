use thiserror::Error;

#[derive(Error, Debug)]
pub enum AuthError 
{
    #[error(transparent)]
    DeserializeError(#[from] serde_json::Error),
    #[error(transparent)]
    IoError(#[from] std::io::Error),
    #[error("Вы не авторизованы")]
    UnauthentificatetedError,
    #[error("Ошибка авторизации -> {0}")]
    AuthorizationError(String),
    #[error("Ошибка обновления refresh_key -> {0}")]
    UpdateRefreshKeyError(String),
    #[error(transparent)]
    UtilitesError(#[from] utilites::error::Error),
    #[error(transparent)]
    JWTError(#[from] jsonwebtoken::errors::Error),
    #[error("Ошибка валидации токена доступа `{0}`")]
    JWTValidateError(String),
    #[error(transparent)]
    AnyhowError(#[from] anyhow::Error),
}

impl serde::Serialize for AuthError 
{
  fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
  where
  S: serde::ser::Serializer,
  {
    serializer.serialize_str(self.to_string().as_ref())
  }
}