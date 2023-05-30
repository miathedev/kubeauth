#Docker file for rust kubeauth
#Multi stage build
#Build stage
FROM rustlang/rust:nightly-buster-slim as builder
WORKDIR /usr/src/kubeauth
COPY . .

#Install pkg-config and openssl-dev
RUN apt-get update && apt-get install -y pkg-config libssl-dev

RUN cargo install --path .


#Final stage
FROM debian:buster-slim
COPY --from=builder /usr/local/cargo/bin/kubeauth /usr/local/bin/kubeauth
ENTRYPOINT ["/usr/local/bin/kubeauth"]

#Command to run build locally using contrib/Dockerfile: docker build -t kubeauth -f contrib/Dockerfile .