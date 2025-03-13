Создание и валидация jwt токена
```rust
let mut jwt  = super::JWT::new_in_file("key.pkcs8");
let id = "1234".to_owned();
let role = "Operator".to_string();
let aud = ["www.google.com", "www.amazon.com"];
let aud_check = ["www.amazon.com"];
let generator = jwt.new_access(&id)
.with_role(&role)
.with_audience(&aud);
let key = generator.gen_key(5);
let valid = jwt.validator()
.with_audience(&aud_check)
.with_subject(&id)
.with_role(role.as_str())
.validate(&key);
```