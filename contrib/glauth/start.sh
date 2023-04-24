#!/bin/bash
set -e

#glauth maybe found under ~/go/bin
export PATH=$PATH:~/go/bin

#check if glauth is installed
if ! command -v glauth &> /dev/null
then
    echo "glauth could not be found"
    exit
fi

#Run glauth
glauth -c sample.cfg