#Docker file for rust kubeauth
#Multi stage build
#Build stage
FROM rustlang/rust:nightly-buster-slim as builder
WORKDIR /usr/src/kubeauth
COPY . .
RUN cargo install --path .

#Final stage
FROM debian:buster-slim
COPY --from=builder /usr/local/cargo/bin/kubeauth /usr/local/bin/kubeauth
ENTRYPOINT ["/usr/local/bin/kubeauth"]
