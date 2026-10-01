# syntax=docker/dockerfile:1
FROM rust:1-bookworm AS development
RUN rustup toolchain install stable --profile minimal --component rustfmt --component clippy
RUN apt-get -o Acquire::ForceIPv4=true -o Acquire::Retries=2 -o Acquire::http::Timeout=20 -o Acquire::https::Timeout=20 update && apt-get -o Acquire::ForceIPv4=true -o Acquire::Retries=2 -o Acquire::http::Timeout=20 -o Acquire::https::Timeout=20 install -y --no-install-recommends protobuf-compiler bubblewrap libseccomp-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /app

FROM development AS builder
ARG TARGETARCH
ARG PRAESIDIONYX_BUILD_PROFILE=release
COPY . .
RUN --mount=type=cache,id=praesidionyx-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=praesidionyx-build-${TARGETARCH},target=/app/target \
    case "$PRAESIDIONYX_BUILD_PROFILE" in release|quickstart) ;; *) exit 1;; esac && \
    cargo build --locked --profile "$PRAESIDIONYX_BUILD_PROFILE" --bin praesidionyxd --bin praesidionyx --bin praesidionyx-tool && \
    mkdir /out && cp "target/$PRAESIDIONYX_BUILD_PROFILE/praesidionyxd" "target/$PRAESIDIONYX_BUILD_PROFILE/praesidionyx" "target/$PRAESIDIONYX_BUILD_PROFILE/praesidionyx-tool" /out/


FROM debian:bookworm-slim AS runtime
RUN apt-get -o Acquire::ForceIPv4=true -o Acquire::Retries=2 -o Acquire::http::Timeout=20 -o Acquire::https::Timeout=20 update && apt-get -o Acquire::ForceIPv4=true -o Acquire::Retries=2 -o Acquire::http::Timeout=20 -o Acquire::https::Timeout=20 install -y --no-install-recommends ca-certificates curl util-linux bubblewrap libseccomp2 && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 praesidionyx && useradd --uid 10001 --gid praesidionyx --no-create-home praesidionyx \
    && mkdir -p /var/lib/praesidionyx && chown praesidionyx:praesidionyx /var/lib/praesidionyx && chmod 0700 /var/lib/praesidionyx
COPY --from=builder /out/praesidionyxd /out/praesidionyx /out/praesidionyx-tool /usr/local/bin/
COPY docker/entrypoint.sh /usr/local/bin/praesidionyx-entrypoint
USER 0:0
ENV PRAESIDIONYX_STATE_DIR=/var/lib/praesidionyx
ENTRYPOINT ["praesidionyx-entrypoint"]
CMD ["praesidionyxd"]
