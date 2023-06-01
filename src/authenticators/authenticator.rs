use std::collections::HashMap;

pub trait Authenticator {
    async fn auth(&self, token: &str, arguments: &HashMap<String, Vec<String>>) -> (bool, String, Vec<String>);
    fn new () -> Self;
}

//List of available authenticators as args
pub const AUTHENTICATORS: &[&str] = &["json_auth", "ldap_auth"];