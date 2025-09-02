FROM rust:latest AS builder

RUN apt update \
    && apt install -y musl-tools \
    && rustup target add x86_64-unknown-linux-musl

# Define build directory
WORKDIR /usr/src/

# Only copy what we need for caching purposes
# Copy Cargo files to cache dependencies
COPY Cargo.toml Cargo.lock ./
# Copy source files
COPY src/ src/
# Copy whole redis-ctl directory
COPY redis-ctl/ redis-ctl/

# Fetch dependencies and cache them
RUN cargo fetch

# Build the binary
#RUN cargo build --release -p dnsblrsd --target x86_64-unknown-linux-musl
RUN cargo build --release -p dnsblrsd --features misp --target x86_64-unknown-linux-musl
RUN cargo build --release -p redis-ctl --target x86_64-unknown-linux-musl

FROM alpine:latest

RUN apk update \
    apk add netcat-openbsd tini

# copy the binaries and make them executable
COPY --from=builder /usr/src/target/x86_64-unknown-linux-musl/release/dnsblrsd /usr/local/bin/dnsblrsd
COPY --from=builder /usr/src/target/x86_64-unknown-linux-musl/release/redis-ctl /usr/local/bin/redis-ctl
RUN chmod +x /usr/local/bin/dnsblrsd /usr/local/bin/redis-ctl

WORKDIR /etc/dnsblrsd
# we also need to copy the blacklist sources for the first initialization
COPY blacklist_sources.json /var/lib/dnsblrsd/blacklist_sources.json

COPY startup.sh /usr/local/bin/startup.sh
RUN chmod +x /usr/local/bin/startup.sh

# NOTE: The docker needs the "NET_BIND_SERVICE" capability to bind to ports under 1024
ENTRYPOINT ["/sbin/tini", "-g", "--"]
CMD ["/usr/local/bin/startup.sh"]
