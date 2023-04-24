#This script is used to generate a self-signed certificate for the kubeauth service.
#The certificate is used to encrypt the communication between the kubeauth service and the kubernetes API server.
#This script is running non-interactively, so it is not possible to enter the password for the certificate.
#All parameters are set in the script. Like company name, country, etc.
#The certificate is valid for 365 days.

#Generate a private key
openssl genrsa -out kubeauth.key 2048

#Generate a certificate signing request
openssl req -new -key kubeauth.key -out kubeauth.csr -subj "/C=DE/ST=Bremen/L=Bremen/O=Delfin/OU=DevOps/CN=kubeauth"

#Generate a self-signed certificate
openssl x509 -req -days 365 -in kubeauth.csr -signkey kubeauth.key -out kubeauth.crt