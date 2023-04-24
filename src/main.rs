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
use rocket::futures;
use rocket::http::Status;
use rocket::response::status;
use rocket::serde::json::Json;
use rocket::State;
use token_review::default_token_review_response;

use crate::authenticators::authenticator::AUTHENTICATORS;
use crate::authenticators::authenticator::Authenticator;
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
    token: &str,
) -> (bool, String, Vec<String>) {
    //Loop through authenticators
    for authenticator in authenticators {
        //match authenticator
        match authenticator.as_str() {
            "json_auth" => {
                //Create json auther
                let json_auther = JsonAuthenticator::new();

                //Run auth
                let (auth, username, groups) = json_auther.auth(token).await;

                //Check if auth was successful
                if auth {
                    //Return true
                    return (true, username, groups);
                }
            }
            "ldap_auth" => {
                //Create ldap auther
                let ldap_auther = authenticators::ldap::LdapAuthenticator::new();

                //Run auth
                let (auth, username, groups) = ldap_auther.auth(token).await;

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

    //Run auth pipeline
    let (auth, username, groups) = run_auth_pipeline(&authenticators, token).await;

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
}

#[launch]
fn rocket() -> _ {
    let (arguments, _flags) = Parser::new().merge_values(true).parse();

    //Get authenticators
    let authenticators: Vec<String> = arguments
        .get("a")
        .or(arguments.get("authenticator"))
        .expect(
            "No authenticators specified. Please specify authenticators using -a or --authenticator",
        )
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

    //Create shared data
    let shared_data = SharedData {
        authenticators: futures::lock::Mutex::new(authenticators_vec),
    };
    rocket::build()
        .manage(shared_data)
        .mount("/", routes![index, validate_token])
}
