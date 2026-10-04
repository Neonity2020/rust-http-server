# syntax=docker/dockerfile:1

# ---------- build stage ----------
FROM rust:1.98-alpine AS builder

# build-base is gcc + make + musl-dev. The C compiler is not optional any more:
# rusqlite's `bundled` feature compiles the SQLite C sources during the build,
# so a C toolchain has to be present even though nothing links against a system
# libsqlite3 at runtime. It only lives in this stage and never ships.
RUN apk add --no-cache build-base

WORKDIR /app

# rustc processes are memory hungry; cap parallelism on small machines.
# 0 lets cargo use every CPU. Override with --build-arg CARGO_BUILD_JOBS=4.
ARG CARGO_BUILD_JOBS=0

# Dependencies first, in their own layer: this only re-runs when the manifests change,
# so editing src/main.rs does not recompile the ~60 dependency crates.
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src \
    && printf 'fn main() {}\n' > src/main.rs \
    && cargo build --release --locked -j "${CARGO_BUILD_JOBS}" \
    && rm -rf src

COPY src ./src
# static/ is pulled in by include_str!, so it must be in the image before the
# crate itself is compiled.
COPY static ./static
# Newer than the stub, otherwise cargo reuses the cached empty binary.
RUN touch src/main.rs \
    && cargo build --release --locked -j "${CARGO_BUILD_JOBS}" \
    && strip target/release/http-server


# ---------- runtime stage ----------
FROM alpine:3.24

RUN apk add --no-cache ca-certificates wget \
    && adduser -D -H -u 10001 appuser

COPY --from=builder /app/target/release/http-server /usr/local/bin/http-server

# The database lives here. It is created up front and chowned to the runtime
# user, because the server runs unprivileged and an unwritable path would only
# surface as a 500 on the first request.
RUN mkdir -p /data && chown appuser:appuser /data

USER appuser:appuser

ENV HOST=0.0.0.0 \
    PORT=3000 \
    RUST_LOG=info,tower_http=info \
    DATABASE_PATH=/data/app.db

EXPOSE 3000

# The probe endpoint is in-process, so it stays green as long as the server is serving.
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD wget -qO- "http://127.0.0.1:${PORT}/health" > /dev/null || exit 1

ENTRYPOINT ["/usr/local/bin/http-server"]