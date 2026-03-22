FROM rust:latest

RUN apt-get update && apt-get install -y \
    cmake build-essential libssl-dev libsodium-dev pkg-config

WORKDIR /app
COPY . .

WORKDIR /app/lib/frostdemo
RUN cargo build --release

WORKDIR /app
RUN mkdir -p build && cd build && cmake .. && make -j$(nproc)

EXPOSE 8080
WORKDIR /app/build