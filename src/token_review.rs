use serde::{Serialize, Deserialize};


//The token review request struct
#[derive(Deserialize)]
pub struct TokenRequest {
    pub apiVersion: String,
    pub kind: String,
    pub spec: TokenReviewRequestSpec
}

//The token review request spec struct
#[derive(Deserialize)]
#[derive(Clone)]
pub struct TokenReviewRequestSpec {
    pub token: String,
}

//The token review response struct
#[derive(Serialize)]
pub struct TokenReviewResponse {
    pub api_version: String,
    pub kind: String,
    pub status: TokenReviewResponseStatus,
}

//The token review response status struct
#[derive(Serialize)]
pub struct TokenReviewResponseStatus {
    pub authenticated: bool,
    pub user: TokenReviewResponseUser,
}

//The token review response user struct
#[derive(Serialize)]
pub struct TokenReviewResponseUser {
    pub username: String,
    pub uid: String,
    pub groups: Vec<String>,
}

//function to generate a default token review response with access denied
pub fn default_token_review_response() -> TokenReviewResponse {
    //Create the token review response
    let token_review_response = TokenReviewResponse {
        api_version: "authentication.k8s.io/v1".to_string(),
        kind: "TokenReview".to_string(),
        status: TokenReviewResponseStatus {
            authenticated: false,
            user: TokenReviewResponseUser {
                username: "".to_string(),
                uid: "".to_string(),
                groups: vec![],
            }
        }
    };

    //Return the token review response
    token_review_response
}

//Function to generate a token review response with access granted and groups
pub fn token_review_response(username: &str, groups: Vec<String>) -> TokenReviewResponse {
    //Create the token review response
    let token_review_response = TokenReviewResponse {
        api_version: "authentication.k8s.io/v1".to_string(),
        kind: "TokenReview".to_string(),
        status: TokenReviewResponseStatus {
            authenticated: true,
            user: TokenReviewResponseUser {
                username: username.to_string(),
                uid: username.to_string(),
                groups,
            }
        }
    };

    //Return the token review response
    token_review_response
}