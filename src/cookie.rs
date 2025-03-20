use std::path::Path;
use cookie::Key;
pub use cookie::{Cookie, CookieJar};
use ring::signature::Ed25519KeyPair;

pub struct CookieService
{
    key: Key
}
impl CookieService
{
    pub fn new_with_key<P: AsRef<Path>>(path: P) -> Self
    {
        if std::fs::exists(path.as_ref()).is_ok_and(|a| a == false)
        {
            let doc = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap();
            std::fs::write(path.as_ref(), doc.as_ref()).unwrap();
        }
        let pkcs8 = utilites::io::read_file_to_binary(path).unwrap();
        let key = Key::from(&pkcs8);
        Self
        {
            key
        }
    }
    /// cookie: ("name", "value")
    pub fn encrypt<C>(&self, mut jar: CookieJar, cookie: C) -> CookieJar
    where
        C: Into<Cookie<'static>>
    {

        jar.private_mut(&self.key).add(cookie);
        jar
    }
    pub fn decrypt<T>(&self, jar: &CookieJar, name: T) -> Option<Cookie<'_>>
    where
        T: AsRef<str>
    {

        jar.private(&self.key).get(name.as_ref())
    }
    
}


#[cfg(test)]
mod tests
{
    use cookie::CookieJar;

    use super::CookieService;

    #[test]
    fn test_cookie()
    {
        logger::StructLogger::new_default();
        let service = CookieService::new_with_key("key.pkcs8");
        let jar = CookieJar::new();
        let cookie = ("name", "value");
        let encrypted = service.encrypt(jar, cookie);
        logger::info!("encrypted: {}", encrypted.get("name").unwrap());
        let decrypted = service.decrypt(&encrypted, "name").unwrap();
        assert_eq!(decrypted.value(), "value");
        //YySnS6nlXXsVQdDbV6apv4sXojeB9FZyTj+ihFM+miIy
        //KXMnqb7BN9HZh3HrdbTyRTUvbepJ9FTYTjRkqIqOpoYm
    }

    #[test]
    fn test_decrypt()
    {
        logger::StructLogger::new_default();
        let service = CookieService::new_with_key("key.pkcs8");
        let mut jar = CookieJar::new();
        jar.add(("name", "KXMnqb7BN9HZh3HrdbTyRTUvbepJ9FTYTjRkqIqOpoYm"));
        let decrypted = service.decrypt(&jar, "name").unwrap();
        assert_eq!(decrypted.value(), "value");
    }
}