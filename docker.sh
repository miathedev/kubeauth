#Script to build the docker container image
#Dockerfile is found in contrib/Dockerfile

#Build the docker image
docker build -f contrib/Dockerfile -t kubeauth .
