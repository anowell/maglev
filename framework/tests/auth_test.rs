use maglev::auth::CookieConfig;

#[test]
fn cookie_config_builds() {
    let _config = CookieConfig::default();
    // Just verify it constructs
}

#[tokio::test]
async fn password_hashing_roundtrip() {
    let password = "secure-password-123".to_string();

    let hash = maglev::auth::hash_password(password.clone())
        .await
        .unwrap();

    assert!(maglev::auth::verify_password(password.clone(), hash.clone())
        .await
        .is_ok());

    assert!(maglev::auth::verify_password("wrong-password".to_string(), hash)
        .await
        .is_err());
}
