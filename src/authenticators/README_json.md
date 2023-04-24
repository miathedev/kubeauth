# How to use json auth

# Env Args
* USERS_FILE_PATH: The path to the json file
* HASHED_PASSWORDS: If the passwords in the json file are hashed or not, true or false as string

## Example users file
```json
{
  "users": [
      {
          "username": "alice",
          "password": "alicepassword",
          "groups": [
              "dev"
          ]
      },
      {
          "username": "bob",
          "password": "bobpassword",
          "groups": [
              "dev"
          ]
      },
      {
          "username": "charlie",
          "password": "charliepassword",
          "groups": [
              "dev"
          ]
      }
  ]
}
```