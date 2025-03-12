mod jwt;
mod error;
mod gen_keys;
pub use error::AuthError;
pub use jwt::{Claims, JWT, TokenData};
//TODO сделать сырую либу для валидации и все! ненадо сюда никакие БД тащить! потом можно как feature сделать надстройку для axum
// // pub async fn is_autentificated(headers: HeaderMap) -> bool
// // {
// //     match headers.get("Authorization") 
// //     {
// //         Some(value) => 
// //         {
// //             let token_str = value.to_str().unwrap_or("").replace("Bearer ", "");
// //             logger::info!("Проверка токена->{}", token_str);
// //             let key = KEY.lock().await;
// //             let v = key.validate_access(&token_str);
// //             if let Ok(_) = v
// //             {
// //                 true
// //             }
// //             else 
// //             {
// //                 let e = v.err().unwrap().to_string();
// //                 logger::error!("{}", &e);
// //                 false
// //             }
// //         },
// //         None => 
// //         {
// //             let e = "Отсуствует заголовок Authorization!";
// //             logger::error!("{}", e);
// //             false
// //         }
// //     }
// // }
// pub async fn is_autentificated(headers: HeaderMap) -> Option<Claims>
// {
//     match headers.get(AUTHORIZATION) 
//     {
//         Some(value) => 
//         {
//             //let token_str = value.to_str().unwrap_or("")[6..].replace("Bearer ", "");
//             let token_str = &value.to_str().unwrap_or("")[6..];
//             logger::info!("Проверка токена->{}", token_str);
//             let key = KEY.lock().await;

//             let v = key.validate_access(&token_str);
//             if let Ok(cl) = v
//             {
//                 Some(cl.claims)
//             }
//             else 
//             {
//                 let e = v.err().unwrap().to_string();
//                 logger::error!("{}", &e);
//                 None
//             }
//         },
//         None => 
//         {
//             let e = "Отсуствует заголовок Authorization";
//             logger::error!("{}", e);
//             None
//         }
//     }
// }
// pub async fn verify_token(headers: HeaderMap) -> Result<(), AuthError> 
// {
//     let is_auth = is_autentificated(headers).await;
//     if is_auth.is_some()
//     {
//         return Ok(());
//     }
//     else 
//     {
//         return Err(AuthError::UnauthentificatetedError);
//     }
// }
// pub async fn get_role<R>(id: &str) -> Result<R, AuthError> where R: for<'de> Deserialize<'de> + Serialize + Send + Unpin + Sync + Clone
// {
//     let role = UserDbo::get_role(id).await?;
//     Ok(role)
// }

// pub async fn create_new_user<R>(user_name: &str, password: &str, name: &str, surn_1: &str, surn_2: &str, role: R) -> Result<(), AuthError> where R: for<'de> Deserialize<'de> + Serialize + Send + Unpin + Sync + Clone
// {
//     let _ = UserDbo::new(user_name, password, name, surn_1, surn_2, role).await?;
//     Ok(())
// }
// pub async fn update_user_info<R>(user_id: &str, password: &str, name: &str, surn_1: &str, surn_2: &str) -> Result<(), AuthError> where R: for<'de> Deserialize<'de> + Serialize + Send + Unpin + Sync + Clone
// {
//     let _ = UserDbo::<R>::update(user_id, password, name, surn_1, surn_2).await?;
//     Ok(())
// }
// pub async fn update_user_role<R>(user_id: &str, role: R) -> Result<(), AuthError> where R: for<'de> Deserialize<'de> + Serialize + Send + Unpin + Sync + Clone
// {
//     let _ = UserDbo::<R>::update_role(user_id, role).await?;
//     Ok(())
// }

// pub async fn initialize_db<R>() -> anyhow::Result<()> where R: for<'de> Deserialize<'de> + Serialize + Send + Unpin + Sync + Clone
// {
//     <UserDbo<R> as SqlOperations>::create().await
// }

// #[derive(Debug, Clone, Serialize, Deserialize)]
// pub struct UpdateTokens
// {
//     pub access: String,
//     pub refresh: String
// }

// pub async fn update_tokens(refresh: &str) -> Result<UpdateTokens, AuthError> 
// {
//     let mut keys = KEY.lock().await;
//     let updated = keys.update_keys(refresh)?;
//     let update_tokens = UpdateTokens
//     {
//         access: updated.1,
//         refresh: updated.0
//     };
//     return  Ok(update_tokens);
// }

// #[derive(Debug, Clone, Serialize)]
// pub struct AuthorizationInfo<R> where R: for<'de> Deserialize<'de> + Serialize + Clone + Send + Sync
// {
//     pub id: String,
//     pub name: String,
//     pub surname_1: String,
//     pub surname_2: String,
//     pub role: R,
//     pub refresh_key: String,
//     pub access_key: String
// }
// ///логин является уникальным но не является id в базе данных
// pub async fn authentificate<'a, R>(login: &'a str, password: &'a str) -> Result<AuthorizationInfo<R>, AuthError> where R: for<'de> Deserialize<'de> + Serialize + Clone + Send + Sync + Unpin + ToString
// {
//     let logged: UserDbo<R>= UserDbo::log_in(login, password).await?;
//     let mut keys = KEY.lock().await;
//     let res = keys.get_pair(&logged.id, logged.user_role.clone());
//     drop(keys);
//     let authorized = AuthorizationInfo
//     {
//         id: logged.id,
//         name: logged.user_name,
//         surname_1: logged.surname_1,
//         surname_2: logged.surname_2,
//         role: logged.user_role,
//         refresh_key: res.0,
//         access_key: res.1
//     };
//     return  Ok(authorized);
// }

// ///логин является уникальным но не является id в базе данных
// pub async fn logout(user_id: &str)
// {
//     let mut keys = KEY.lock().await;
//     let _ = keys.del_user_keys(user_id);
// }
