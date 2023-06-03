use std::{collections::HashMap, env, fs::File, io::BufReader, path::Path};

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
    hashed_pw: bool,
}

impl Authenticator for JsonAuthenticator {
    async fn auth(&self, token: &str) -> (bool, String, Vec<String>) {
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

            //Get state if hashed is enabled via arguement

            //If hashed password is set, hash the password and compare it to the hashed password, otherwise plain compare
            if self.hashed_pw {
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

    
    fn new (arguments: HashMap<String, Vec<String>>) -> Self {
        println!("Loading json_auth authenticator");
        
        let users_file_path: String;
        //Get -u --users-file-path argument
        match arguments.get("json_user_file_path") {
            Some(path) => {
                //Check if users_file_path is set
                if path.is_empty() {
                    println!("--json_user_file_path is required for json_auth authenticator");
                    std::process::exit(1);
                }
                //Check if users_file_path is valid
                if !Path::new(&path[0]).exists() {
                    println!("--json_user_file_path is not valid");
                    std::process::exit(1);
                }
                //Set users_file_path
                users_file_path = path[0].clone();
            },
            None => {
                println!("--json_user_file_path is required for json_auth authenticator");
                std::process::exit(1);
            }
        }
        
        //Get the users
        let users = JsonAuthenticator::get_users(&users_file_path);

        let mut hashed = false;
        //Get --json_hashed_pw argument
        match arguments.get("json_hashed_pw") {
            Some(hashed_pw) => {
                //Check if hashed_pw is true
                if hashed_pw[0] == "true" {
                    //Set hashed to true
                    hashed = true;
                }
            },
            None => ()
        }
        //Return the users auther
        JsonAuthenticator {
            users,
            hashed_pw: hashed
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