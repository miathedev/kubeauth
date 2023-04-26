use std::{collections::HashMap, env};



use serde::{Deserialize, Serialize};

use super::authenticator::Authenticator;

use ldap3::{LdapConnAsync, Scope, SearchEntry};
/*
This is a ldap authenticator that can be used to authenticate users using ldap.
Using ldap3 lib from crates.io
*/

fn replace_vars(filter: &str, vars: &HashMap<String, String>) -> String {
    let mut result = String::new();
    let mut chars = filter.chars();
    while let Some(c) = chars.next() {
        if c == '$' {
            if let Some('{') = chars.next() {
                let mut var_name = String::new();
                while let Some(c) = chars.next() {
                    if c == '}' {
                        if let Some(val) = vars.get(&var_name[..]) {
                            result.push_str(val);
                        }
                        break;
                    }
                    var_name.push(c);
                }
            } else {
                result.push('$');
            }
        } else {
            result.push(c);
        }
    }
    result
}

#[derive(Serialize, Deserialize)]
pub struct LdapAuthenticator {
    ldap_server_url: String,
    service_account_username: String,
    service_account_password: String,
    base_dn: String,
}

//Default return value for ldap authenticator
//const default_return: (bool, String, Vec<String>) = (false, String::from(""), vec![]);

impl Authenticator for LdapAuthenticator {
    async fn auth(&self, token: &str) -> (bool, String, Vec<String>) {
        //Split token by :
        let token_split: Vec<&str> = token.split(":").collect();

        //Get username
        let username = String::from(token_split[0]);

        //Check if username is alphanumeric
        if !LdapAuthenticator::contains_only_alphanumeric(username.clone()) {
            println!("Username contains non alphanumeric characters, aborting, maybe ldap injection attempt");
            return (false, String::from(""), vec![]);
        }

        //Get password
        let password = token_split[1];

        //Create ldap connection
        let (conn, mut ldap) = LdapConnAsync::new(&self.ldap_server_url).await.unwrap();
        ldap3::drive!(conn);

        //bind string format
        let bind_string = format!("cn={},{}", username, &self.base_dn);

        //try to bind to user and check if it is successful, to check if username and password are correct
        let bind = ldap.simple_bind(&bind_string, password).await;
        match bind {
            Ok(ldapResult) => {
                //RC 49 means invalid credentials
                if ldapResult.rc == 49 {
                    println!("Invalid credentials");
                    return (false, String::from(""), vec![]);
                } //RC 0 means success
                else if ldapResult.rc == 0 {
                    println!("Successfully bound to user");
                } else {
                    println!("Unknown error");
                    return (false, String::from(""), vec![]);
                }
                println!("Successfully bound to user");
            }
            Err(e) => {
                println!("Failed to bind to user");
                return (false, String::from(""), vec![]);
            }
        }

        //bind string !format
        let bind_string = format!("cn={},{}", &self.service_account_username, &self.base_dn);

        let bind = ldap
            .simple_bind(&bind_string, &self.service_account_password)
            .await;

        //TODO: this check is not working, even if bind fails, it still returns Ok...
        match bind {
            Ok(ldapResult) => {
                //RC 49 means invalid credentials
                if ldapResult.rc == 49 {
                    println!("Invalid credentials");
                    return (false, String::from(""), vec![]);
                } //RC 0 means success
                else if ldapResult.rc == 0 {
                    println!("Successfully bound to service account to get groups");
                } else {
                    println!("Unknown error");
                    return (false, String::from(""), vec![]);
                }
                println!("Successfully bound to user");
            }
            Err(e) => {
                println!("Failed to bind to user");
                return (false, String::from(""), vec![]);
            }
        }

        //Build filter string, use usually not used symbols for variable replacement
        //Example: (&(objectClass=person)(uid={}))
        let mut vars: HashMap<String, String> = HashMap::new();
        vars.insert(String::from("username"), username.clone());

        //Get filter from env
        let filter = env::var("LDAP_FILTER").unwrap_or("cn=${username}".to_string());
        let filter = replace_vars(&filter, &vars);

        //Search for cn=username
        let mut search = ldap
            .streaming_search(
                &self.base_dn, //example dc=example,dc=com
                Scope::Subtree,
                &filter,
                vec!["l"],
            )
            .await
            .unwrap();

        //Capture error
        let entry = search.next().await;
        //Completly unwrap entry but handle errors
        let entry = match entry {
            Ok(entry) => entry,
            Err(e) => {
                println!("Error while searching for user: {}", e);
                return (false, String::from(""), vec![]);
            }
        };

        
        let entry = match entry {
            Some(entry) => entry,
            None => {
                println!("No entry found, failed to find user");
                return (false, String::from(""), vec![]);
            }
        };

        //Convert entry to SearchEntry
        let entry = SearchEntry::construct(entry);

        //println!("entry: {:?}", entry);
        //Get ou from entry.dn

        //Split by comma
        let entry_vals: Vec<&str> = entry.dn.split(",").collect();

        //Each val of entry vals is a key value pair, split by =
        //Search for all ou= values and save them to a vec
        let mut groups: Vec<String> = vec![];
        for val in entry_vals {
            let val: Vec<&str> = val.split("=").collect();
            if val[0] == "ou" {
                groups.push(val[1].to_string());
            }
        }
        //Print groups
        //println!("groups: {:?}", groups);

        print!("Successfully authenticated user {} with ldap", username);

        return (true, String::from(username), groups);
    }

    fn new() -> Self {
        //Get ldap server url, default to ldap://localhost:389
        let ldap_server_url =
            env::var("LDAP_SERVER_URL").unwrap_or("ldap://localhost:3893".to_string());

        //Get service account username, default to admin, this is the username of the service account that is used to authenticate to the ldap server
        //In glauth this is the serviceuser using the sample config
        let service_account_username =
            env::var("LDAP_SERVICE_ACCOUNT").unwrap_or("serviceuser".to_string());

        //Get service account password, default to mysecret, this is the password of the service account that is used to authenticate to the ldap server
        //In glauth this is the serviceuser using the sample config
        let service_account_password =
            env::var("LDAP_SERVICE_ACCOUNT_PW").unwrap_or("mysecret".to_string());

        //Get the base dn, default to dc=glauth,dc=com, this is the base dn that is used to search for users
        //In glauth this is the dc=glauth,dc=com using the sample config
        let base_dn = env::var("LDAP_BASE_DN").unwrap_or("dc=glauth,dc=com".to_string());

        Self {
            ldap_server_url,
            service_account_username,
            service_account_password,
            base_dn,
        }
    }
}

impl LdapAuthenticator {
    pub fn contains_only_alphanumeric(username: String) -> bool {
        for c in username.chars() {
            if !c.is_alphanumeric() {
                return false;
            }
        }
        true
    }
}
