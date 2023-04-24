# How to use the ldap auth

## Env Args
* LDAP_SERVER_URL: The url of the ldap server
* LDAP_SERVICE_ACCOUNT: The service account to use to connect to the ldap server
* LDAP_SERVICE_ACCOUNT_PW: The password of the service account
* LDAP_BASE_DN: The base dn to use to find the user
* LDAP_FILTER: The filter to use to find the user

## LDAP Filter example
The filter is used to find the user in the ldap server. The filter has active substitutions. The substitutions are:
* ${username}: The username of the user

So you could potentially create filters like:
```
(&(objectClass=person)(uid=${username}))
```
## Service account
The service account must have the rights to search a user in the ldap server.

# Disclaimer
This is a work in progress. It is not ready for production use.
And i am not a professional in ldap. So if you have any suggestions, please let me know.