<img class="img-fluid" width="100" height="100" src="./images/logo.png" alt="img-verification">

___
# How to install kubeauth

## Releases
You can download the latest release from the release page. The master branch is the development branch. So it may be unstable. Which should be often the case. So i recommend to use the latest release.

## Arguments
```
KubeAuth is a simple authentication provider for kubernetes.
It is used to validate tokens sent by the kubernetes api server.
Usage: kubeauth -a <authenticator> [-p <port>] [-ip <ip>]
Authenticators:
        json_auth: Uses a json file to authenticate users
        ldap_auth: Uses ldap to authenticate users
Flags:
        -h, --help: Prints this help message
Arguments:
        -a, --authenticator: The authenticator to use
        -p, --port: The port to listen on
        -ip, --ip: The ip to listen on
        -crt, --cert: The certificate to use
        -key, --key: The cert key to use
        json_auth:
                --json_user_file_path: The users json file to use
        ldap_auth: NOT YET IMPLEMENTED, they are just reserved
                --ldap_host: The ldap host to use
                --ldap_port: The ldap port to use
                --ldap_base_dn: The ldap base dn to use
                --ldap_user_dn: The ldap user dn to use
                --ldap_password: The ldap searchuser password to use
Example:
        kubeauth -a json_auth -p 8000 -ip 0.0.0.0 -crt cert.pem -key key.pem -u users.json
```
## What is kubeauth
kubeauth is a experimental simple authentication backend for kubernetes. It is written in rust and uses the rocket framework. It is designed to be used in conjunction with the kubeapi server using webhook token authentication.

## How does it work
kubeauth is a simple http server. It listens on port 8000 by default. It has basically one endpoint. The endpoint ```token``` is used to authenticate a user using a Webhook Token Review Request send from the kubeapi server. 

The user that has to be authenticated has a configured token. The token is send to the kubeapi server.

Example kubeconfig:
```
- name: kubernetes-webhook
  user:
    #Token
    token: "alice:alicepassword"
```

The client sends the token in his request to the kubeapi server.

Then the kubeapi server will send a Webhook Token Review Request to kubeauth to check if the token is valid. Kubeauth will then check if the token is valid and if the user is allowed to authenticate. If the token is valid and the user is allowed to authenticate, kubeauth will send a Webhook Token Review Response back to the kubeapi server. The kubeapi server will then authenticate the user.

## Why has kubeauth been created
In Kubernetes there are by default no real groups. There are only roles and rolebindings. So if you want to create a group of users, you have to create a rolebinding for each SINGLE user. This is not very handy. So i created kubeauth. Groups are actually provided by the authentication backend. So you can create groups of users and assign roles to the groups. This is much more handy and convenient.

This is where kubeauth comes in, it is a simple authentication backend for kubernetes. It is designed to be used in conjunction with the kubeapi server using webhook token authentication. On authentication kubeauth will check, if the user is allowed to authenticate - and if the token is valid. If the user is allowed to authenticate and the token is valid, kubeauth will send a Webhook Token Review Response back to the kubeapi server. Including groups! The kubeapi server will then authenticate the user and assign the groups to the user.

This is usefull for kyverno policies as well! In a project i wanted to restrict users of a user group to mount a hostPath to a specific host path. I had to create one rule per user. When i used kubectl, the cli listed me every single rule applied for each user. Like why? And it was hard to manage that many policies. So afterwards, creating kubeauth came in handy. Groups are awesome.

## Authentication methods using kubeauth
kubeauth supports the following authentication methods:
  * Json file (see contrib/users.json)

Currently there is planned support for the following authentication methods:
  * LDAP (Experimental stage)

  But feel free to contribute. This is an open source project and has been created originally for my bachelor thesis. So i dont have the time to implement all the features i want to implement. But i will try to implement as much as possible.

Yet, authentication methods can be added easily. You just have to implement the trait ```Authenticator``` and add the new authenticator to the ```Authenticator::auth``` function.

Authenticators are located in the ```src/authenticators``` directory.

Authenticators are loaded dynamically. So you dont have to recompile kubeauth to add a new authenticator you want to use. But the authenticator implementation has to be compiled.

### Set the authentication method
The authentication method is set using arguments. You can set the authentication method using the ```-a``` argument. The argument takes a string as value. The string is the name of the authenticator. The authenticator has to be located in the ```src/authenticators``` directory.

Example:
```kubeauth -a json_auth -a ldap_auth``` will load the json_auth and ldap_auth authenticators.

### Downloads
You can download the latest release from the [releases page](https://github.com/miathedev/kubeauth/releases).

### Configure the authentication methods
Currently kubeauth supports the following authentication methods:
  * Json file (see contrib/users.json) see [src/authenticators/README_json.md](src/authenticators/README_json.md)
  * LDAP (Experimental) see [src/authenticators/README_ldap.md](src/authenticators/README_ldap.md)

Each authentication method has environment variables associated with it. The environment variables are used to configure the authentication method. For names of the environment variables see the README.md of the authentication method.

#### Try it out
If you want to try, if the token auth works, you can use 
```
kubectl get pods --token=alice:alicepassword
```
This will authenticate you as user alice.

You can also use curl to test the token auth. Example:
```
curl --insecure -X POST -H "Content-Type: application/json" -d '{"apiVersion":"authentication.k8s.io/v1","kind":"TokenReview","metadata":{"creationTimestamp":null},"spec":{"token":"alice:alicepassword"}}' https://localhost:8000/token
```
## Prerequisites
There are a few options to install kubeauth. The current working method is installing kubeauth as standalone binary and let kubespray set all the necessary configuration. The other option is to install kubeauth as a kubernetes deployment. This is not yet fully tested and documented.

And i honestly dont know if its a good idea to install kubeauth as a kubernetes deployment since it is used as authentication backend for kubernetes. So if kubeauth is down, you cant authenticate to kubernetes anymore.

But im open for suggestions and pull requests.

## Install kubeauth as standalone binary
```cargo build --release``` will build the binary in the target/release directory. Copy the binary to a location of your choice and make sure it is in your PATH.

There is a systemd service file in the contrib directory. Copy it to /etc/systemd/system and adapt the path to the kubeauth binary. Then run ```systemctl enable kubeauth``` and ```systemctl start kubeauth```.

## Install kubeauth as kubernetes deployment
This is not yet fully tested and documented. But the idea is to install kubeauth as a kubernetes deployment. There is a kubernetes deployment file in the contrib directory. Copy it to a location of your choice and adapt the path to the kubeauth binary. Then run ```kubectl apply -f kubeauth-deployment.yaml```.

## Install kubeauth as docker container
This is not yet fully tested and documented. But the idea is to install kubeauth as a docker container. There is a dockerfile in the contrib directory. Copy it to a location of your choice and adapt the path to the kubeauth binary. Then run ```docker build -f contrib/Dockerfile -t kubeauth .``` and ```docker run -d --name kubeauth kubeauth```.

# Configure the cluster
Currently i honestly didnt fully understand how to configure the cluster to use kubeauth. But i found kubespray to help me with that. So i used kubespray to configure the cluster. I will try to explain how i did it.

## Install kubespray
Follow the instructions on the kubespray github page to install kubespray. I used the master branch.

## Configure kubespray
The magic lies behind ```group_vars/all/all.yml```. There are a few options to configure the cluster. I will try to explain the most important ones.

You need to edit: 
```
kube_webhook_token_auth: true
kube_webhook_token_auth_url_skip_tls_verify: true
kube_webhook_token_auth_url: https://yourhost:8000/token
```

Kubespray will then do the magic and configure the cluster to use kubeauth.

____

I had to set ```kube_webhook_token_auth_url_skip_tls_verify: true``` because i didnt have a valid certificate for my kubeauth server. You may want to change this to false and use a valid certificate.

The certificate is set in Rocket.toml. You can change the path to the certificate in Rocket.toml.

____
Kubeauth doesnt have to run on the same host as the kubeapi server. You can run kubeauth on any host you want. You just have to make sure that the kubeapi server can reach the kubeauth server.

Also, when kubeauth doesnt run, the kubeapi will still work because authentification plugins are chained in kubernetes. So if kubeauth is down, the next authentification plugin will be used. For example the x509 authentification plugin using certificates.

# Build dependencies

```
sudo apt-get install libsasl2-dev libldap2-dev libssl-dev pkg-config
```

# Disclaimer
I am not a rust expert. So there may be some bad code in this project. Feel free to contribute and improve the code. I will try to improve the code as much as possible and im open for suggestions and pull requests.

# License
This project is licensed under the GPL-3.0 License - see the license.md file for details