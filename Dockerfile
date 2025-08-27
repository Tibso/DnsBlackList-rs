FROM rust:latest AS dnsblrsd-builder
# define build directory
WORKDIR /usr/src/dnsblrsd
# Copy only Cargo config files to cache dependencies
COPY Cargo.toml Cargo.lock .
# Fetch dependencies and cache this layer if Cargo files unchanged
RUN cargo fetch
# copy source files in the build directory
COPY src src
# build the binary
RUN cargo build --release
#RUN cargo build --release --features misp

FROM rust:latest AS redisctl-builder
WORKDIR /usr/src/redis-ctl
COPY redis-ctl/Cargo.toml redis-ctl/Cargo.lock .
RUN cargo fetch
COPY redis-ctl/src src
RUN cargo build --release

FROM alpine:latest

# copy the binaries and make them executable
COPY --from=dnsblrsd-builder /usr/src/dnsblrsd/target/release/dnsblrsd /usr/local/bin/dnsblrsd
COPY --from=redisctl-builder /usr/src/redis-ctl/target/release/redis-ctl /usr/local/bin/redis-ctl
RUN chmod +x /usr/local/bin/dnsblrsd /usr/local/bin/redis-ctl

WORKDIR /etc/dnsblrsd
# the binary will look for its configuration in its workdir
COPY dnsblrsd.conf .
# we also need to copy the blacklist sources for the first initialization
COPY blacklist_sources.json . 

# NOTE: The docker needs the "NET_BIND_SERVICE" capability to bind to ports under 1024

COPY startup.sh /startup.sh
RUN chmod +x /startup.sh
ENTRYPOINT ["/startup.sh"]

