FROM ubuntu:24.04

# Install all necessary dependencies for C++, Rust, and Crypto
RUN DEBIAN_FRONTEND=noninteractive apt-get update && \
    apt-get install -y build-essential cmake libssl-dev cargo curl libsodium-dev

WORKDIR /app
COPY . /app

# Build the frost crypto library
WORKDIR /app/lib/frostdemo
RUN rm -f Cargo.lock && cargo build --release

# Build the project
WORKDIR /app
RUN mkdir build && cd build && cmake .. && make

# Expose the base port
EXPOSE 8080

WORKDIR /app/build