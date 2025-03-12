// pub fn deserialize_uuid<'de, D, T>(de: D) -> Result<Option<T>, D::Error>
// where
//     D: Deserializer<'de>,
//     T: FromStr,
//     T::Err: fmt::Display,
// {
//     let opt = Option::<String>::deserialize(de)?;
//     match opt.as_deref() 
//     {
//         None | Some("null") | Some("NULL") => Ok(None),
//         Some(s) => FromStr::from_str(s).map_err(de::Error::custom).map(Some),
//     }
// }
pub fn deserialize_uuid<'de, D>(deserializer: D) -> Result<uuid::Uuid, D::Error>
where
    D: serde::de::Deserializer<'de>,
{
    let s: &str = serde::de::Deserialize::deserialize(deserializer)?;
    if let Ok(uid) = uuid::Uuid::parse_str(s)
    {   
        Ok(uid)
    }
    else 
    {
        Err(serde::de::Error::custom(format!("Неверный формат uuid: {}", s)))
    }
}
