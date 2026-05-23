// config/mod.rs — TOML configuration schema + loader + validator

pub mod loader;
pub mod schema;
pub mod validator;

pub use loader::load_config;
pub use validator::validate_config;

