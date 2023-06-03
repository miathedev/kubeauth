#!/bin/bash

# Generate a self-signed certificate for the server to use.
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
