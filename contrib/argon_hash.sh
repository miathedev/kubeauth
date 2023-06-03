#!/bin/bash

# Script to generate a hash of a password using Argon2i.
# Check if argon2 is installed.
if ! command -v argon2 >/dev/null 2>&1; then
    echo "Error: argon2 is not installed. Please install it and try again."
    exit 1
fi

echo "Enter the password to hash: "
read -s password
echo "Enter the salt to use: "
read -s salt
echo "Enter the number of iterations to use: "
read iterations