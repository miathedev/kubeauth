use std::{collections::HashMap, env, fs::File, io::BufReader};

use argon2::{
    password_hash::{
        rand_core::OsRng, PasswordHasher, SaltString
    },
    Argon2
};

use serde::{Serialize, Deserialize};

use super::authenticator::Authenticator;

//The user struct
#[derive(Serialize, Deserialize)]
struct User {
    username: String,
    password: String,
    groups: Vec<String>,
}

#[derive(Serialize, Deserialize)]

struct Users {
    users: Vec<User>,
}

//Auther struct for using users.json
pub struct JsonAuthenticator {
    users: HashMap<String, User>,
}

impl Authenticator for JsonAuthenticator {
    async fn auth(&self, token: &str, arguments: &HashMap<String, Vec<String>>) -> (bool, String, Vec<String>) {
        //Split token by :
        let token_split: Vec<&str> = token.split(":").collect();

        //Get username
        let username = token_split[0];

        //Get password
        let password = token_split[1];

        println!("Authenticating user {} with json", username);
        //Get the users
        let users = &self.users;

        //Check if the user exists
        if users.contains_key(username) {
            //Get the user
            let user = users.get(username).unwrap();

            //Get state if hashed is enabled
            let hashed = env::var("HASHED_PASSWORDS").unwrap_or("false".to_string()) == "true";

            //If hashed password is set, hash the password and compare it to the hashed password, otherwise plain compare
            if hashed {
                //Get salt from env var, default to pepper
                let salt = SaltString::generate(&mut OsRng);
                let argon2 = Argon2::default();
                //Hash the password
                
                let hashed_password = argon2.hash_password(password.as_bytes(), &salt);

                if hashed_password.is_err() {
                    println!("Failed to hash password");
                    return (false, String::from(""), vec![]);
                }

                //Check if the password is correct
                if user.password == hashed_password.unwrap().to_string() {
                    //Return true
                    return (true, String::from(username), user.groups.clone());
                }
            } else {
                //Check if the password is correct
                if user.password == password {
                    //Return true
                    return (true, String::from(username), user.groups.clone());
                }
            }
        }

        //Return false
        return (false, String::from(""), vec![]);
    }

    
    fn new () -> Self {
        //Get the users file path, default to users.json
        let users_file_path = env::var("USERS_FILE_PATH").unwrap_or("users.json".to_string());

        //Check if file exists
        if !std::path::Path::new(&users_file_path).exists() {
            panic!("Users file does not exist or env var USERS_FILE_PATH is not set");
        }

        //Get the users
        let users = JsonAuthenticator::get_users(&users_file_path);

        //Return the users auther
        JsonAuthenticator {
            users,
        }
    }
}

impl JsonAuthenticator {
    //Get the users from the users file
    fn get_users(users_file_path: &str) -> HashMap<String, User> {
        //Open the users file
        let users_file = File::open(users_file_path).expect("Failed to open users file");

        //Read the users file
        let users_file_reader = BufReader::new(users_file);

        //Deserialize the users file
        let users: Users = serde_json::from_reader(users_file_reader).expect("Failed to deserialize users file");

        //Create the users map
        let mut users_map: HashMap<String, User> = HashMap::new();

        //Add the users to the users map
        for user in users.users {
            users_map.insert(user.username.clone(), user);
        }

        //Return the users map
        users_map
    }
}