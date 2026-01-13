use maglev::config::EnvConfig;
use serde::Deserialize;

#[derive(Debug, Deserialize, PartialEq)]
struct TestConfig {
    host: String,
    port: u16,
    debug: bool,
}

#[test]
fn env_config_loads_from_environment() {
    std::env::set_var("HOST", "localhost");
    std::env::set_var("PORT", "8080");
    std::env::set_var("DEBUG", "true");

    let config = TestConfig::from_env().unwrap();

    assert_eq!(config.host, "localhost");
    assert_eq!(config.port, 8080);
    assert_eq!(config.debug, true);

    std::env::remove_var("HOST");
    std::env::remove_var("PORT");
    std::env::remove_var("DEBUG");
}

#[test]
fn env_config_with_prefix() {
    std::env::set_var("APP_HOST", "0.0.0.0");
    std::env::set_var("APP_PORT", "3000");
    std::env::set_var("APP_DEBUG", "false");

    let config = TestConfig::from_env_with_prefix("APP").unwrap();

    assert_eq!(config.host, "0.0.0.0");
    assert_eq!(config.port, 3000);
    assert_eq!(config.debug, false);

    std::env::remove_var("APP_HOST");
    std::env::remove_var("APP_PORT");
    std::env::remove_var("APP_DEBUG");
}
