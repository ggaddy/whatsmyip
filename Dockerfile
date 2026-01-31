# syntax=docker/dockerfile:1
ARG RUST_VERSION=1.90

FROM docker.io/library/rust:${RUST_VERSION}-slim-bookworm AS build
WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN cargo build --release --locked

FROM gcr.io/distroless/cc-debian12:nonroot
WORKDIR /app
COPY --from=build /app/target/release/whatsmyip /app/whatsmyip

ENV RUST_LOG=info
EXPOSE 8080
USER nonroot
ENTRYPOINT ["/app/whatsmyip"]
