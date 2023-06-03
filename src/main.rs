#![feature(proc_macro_hygiene, decl_macro)]
#![feature(async_fn_in_trait)]

#[macro_use]
extern crate rocket;

/*
This application is used as authentication provider using the kubernetes webhook authentication.
It is used to validate the token sent by the kubernetes api server.
A token might be username:password or even a jwt token.
How tokens are handled is up to the user of this application.
See authenticators for examples on how to handle tokens.

All rights reserved to the author of this application.
Mia Metzler <mia@metzler.systems>

This application is licensed under the MIT license.
*/

//Import the required libraries
use core::str;
use std::collections::HashMap;
use authenticators::ldap::LdapAuthenticator;
use rocket::config::CipherSuite;
use rocket::config::Config as RocketConfig;
use rocket::config::TlsConfig;
use rocket::futures;
use rocket::http::Status;
use rocket::response::status;
use rocket::serde::json::Json;
use rocket::State;
use token_review::default_token_review_response;

use crate::authenticators::authenticator::Authenticator;
use crate::authenticators::authenticator::AUTHENTICATORS;
use crate::authenticators::json::JsonAuthenticator;
use crate::token_review::TokenRequest;
use crate::token_review::TokenReviewResponse;
use cmdparser::Parser;

pub mod authenticators;
pub mod token_review;

//The index route
//This route is used to check if the application is running
#[get("/")]
async fn index() -> &'static str {
    "KubeAuth is running!"
}

//fn to run authenticator pipeline
async fn run_auth_pipeline(
    authenticators: &Vec<String>,
    arguments: &HashMap<String, Vec<String>>, //Arguments are or could be used to pass parameters to authenticators
    shared: &State<SharedData>,
    token: &str,
) -> (bool, String, Vec<String>) {
    //Loop through authenticators
    for authenticator in authenticators {
        //match authenticator
        match authenticator.as_str() {
            "json_auth" => {
                //Create json auther
                let json_auth = shared.json_auth_mod.lock().await;

                //Run auth
                let (auth, username, groups) = json_auth.auth(token).await;

                //Check if auth was successful
                if auth {
                    //Return true
                    return (true, username, groups);
                }
            }
            "ldap_auth" => {
                //Create ldap auther
                let ldap_auth = shared.ldap_auth_mod.lock().await;

                //Run auth
                let (auth, username, groups) = ldap_auth.auth(token).await;

                //Check if auth was successful
                if auth {
                    //Return true
                    return (true, username, groups);
                }
            }
            _ => {
                //Return false
                return (false, String::from(""), vec![]);
            }
        }
    }

    //Return false
    return (false, String::from(""), vec![]);
}

//The validate token route
//This route is used to validate the token
#[post("/token", data = "<tokenReq>")]
async fn validate_token(
    tokenReq: Json<TokenRequest>,
    shared: &State<SharedData>,
) -> status::Custom<Json<TokenReviewResponse>> {
    //Get the token
    let token = &tokenReq.spec.token;

    //Get authenticators from rocket state
    let authenticators = shared.authenticators.lock().await;

    //Get arguments from rocket state
    let arguments = shared.arguments.lock().await;

    //Run auth pipeline
    let (auth, username, groups) = run_auth_pipeline(&authenticators, &arguments, &shared, token).await;

    //Check if auth was successful
    if auth {
        //Return true
        return status::Custom(
            Status::Ok,
            Json(token_review::token_review_response(&username, groups)),
        );
    }

    //Run auth pipeline

    return status::Custom(Status::Unauthorized, Json(default_token_review_response()));
}

struct SharedData {
    authenticators: futures::lock::Mutex<Vec<String>>,
    arguments: futures::lock::Mutex<HashMap<String, Vec<String>>>,
    json_auth_mod: futures::lock::Mutex<JsonAuthenticator>,
    ldap_auth_mod: futures::lock::Mutex<LdapAuthenticator>,
}

#[launch]
fn rocket() -> _ {
    let (arguments, _flags) = Parser::new().merge_values(true).parse();

    //If -h or --help is set, print help and exit
    if arguments.get("h").or(arguments.get("help")).is_some_and(|x| x.len() > 0) || _flags.len() > 0
    {
        //Print help
        println!("KubeAuth is a simple authentication provider for kubernetes.");
        println!("It is used to validate tokens sent by the kubernetes api server.");
        println!("Usage: kubeauth -a <authenticator> [-p <port>] [-ip <ip>]");
        println!("Authenticators:");
        println!("\tjson_auth: Uses a json file to authenticate users");
        println!("\tldap_auth: Uses ldap to authenticate users");
        println!("Flags:");
        println!("\t-h, --help: Prints this help message");
        println!("Arguments:");
        println!("\t-a, --authenticator: The authenticator to use");
        println!("\t-p, --port: The port to listen on");
        println!("\t-ip, --ip: The ip to listen on");
        println!("\t-crt, --cert: The certificate to use");
        println!("\t-key, --key: The cert key to use");

        //Authenticator specific arguments
        println!("\tjson_auth:");
        println!("\t\t--json_user_file_path: The users json file to use");

        //TODO: Add ldap arguments, there are not implemented yet
        println!("\tldap_auth:");
        println!("\t\t--ldap_url: The ldap host url to use");
        println!("\t\t--ldap_bind_dn: The ldap bind dn to use");
        println!("\t\t--ldap_bind_password: The ldap bind password to use");
        println!("\t\t--ldap_base_dn: The ldap base dn to use");
        println!("\t\t--ldap_filter: The ldap filter to use");
        

        println!("Example:");
        println!("\tcargo run -- -a json_auth --json_user_file_path users.json -crt contrib/cert.pem -key contrib/key.pem");
        //Exit
        std::process::exit(0);
    }
    //Get authenticators, no default param and required
    let authenticators: Vec<String> = arguments
        .get("a")
        .or(arguments.get("authenticator"))
        .expect(
            "No authenticators specified. Please specify authenticators using -a or --authenticator",
        )
        .to_vec();

    //Get optional port argument, default to 8000
    let port: Vec<String> = arguments
        .get("p")
        .or(arguments.get("port"))
        .unwrap_or(&vec!["8000".to_string()])
        .to_vec();

    //Get optional ip argument, default to 0.0.0.0
    let ip = arguments
        .get("ip")
        .or(arguments.get("ip"))
        .unwrap_or(&vec!["0.0.0.0".to_string()])
        .to_vec();

    //Get required cert argument
    let cert = arguments
        .get("cert")
        .or(arguments.get("crt"))
        .expect("Cert arg is required")
        .to_vec();

    //Get required key argument
    let key = arguments
        .get("key")
        .expect("Cert Key arg is required")
        .to_vec();

    //Check if authenticators are valid
    for authenticator in &authenticators {
        //Check if authenticator is valid and is in AUTHENTICATORS
        if !AUTHENTICATORS.contains(&authenticator.as_str()) {
            //Print error
            println!(
                "Authenticator {} is not valid. Possible authenticators are: {:?}",
                authenticator, AUTHENTICATORS
            );

            //Exit
            std::process::exit(1);
        }
    }

    //Create vector of authenticators
    let mut authenticators_vec: Vec<String> = Vec::new();

    //Loop through authenticators
    for authenticator in authenticators {
        //Add authenticator to vector
        authenticators_vec.push(authenticator.to_string());
    }

    //Print authenticators
    println!("Authenticators: {:?}", authenticators_vec);

    let test = arguments.clone();
    let test2 = arguments.clone();
    //Create shared data
    //TODO: For example json_auth_mod can be not selected, but it still expects the arguments and will panic if not.
    //TODO: Maybe add a check if authenticator is selected and if not, don't add it to shared data
    let shared_data = SharedData {
        authenticators: futures::lock::Mutex::new(authenticators_vec),
        arguments: futures::lock::Mutex::new(arguments),
        json_auth_mod: futures::lock::Mutex::new(JsonAuthenticator::new(test)),
        ldap_auth_mod: futures::lock::Mutex::new(LdapAuthenticator::new(test2)),
    };

    let mut config = RocketConfig::release_default();
    //Configure port
    match port[0].parse() {
        Ok(port) => config.port = port,
        Err(_) => {
            println!("Port is not a valid number");
            std::process::exit(1);
        }
    }

    //Configure ip
    match ip[0].parse() {
        Ok(ip) => config.address = ip,
        Err(_) => {
            println!("IP is not a valid ip");
            std::process::exit(1);
        }
    }

    //Check if cert and key are valid paths and valid certs
    if !std::path::Path::new(&cert[0]).exists() {
        println!("Cert path is not valid");
        std::process::exit(1);
    }
    if !std::path::Path::new(&key[0]).exists() {
        println!("Cert key path is not valid");
        std::process::exit(1);
    }

    //Configure cert and key, both are required, no unwrap
    let tls_config = TlsConfig::from_paths(cert[0].clone(), key[0].clone());
    config.tls = Some(tls_config);



    
    //config   
    rocket::custom(config)
        .manage(shared_data)
        .mount("/", routes![index, validate_token])
        //Set port and listen on all interfaces
}
