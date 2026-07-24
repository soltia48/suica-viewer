# syntax=docker/dockerfile:1

FROM rust:1-bookworm

ARG UID=1000
ARG GID=1000

RUN --mount=type=cache,target=/var/lib/apt/,sharing=locked \
    --mount=type=cache,target=/var/cache/apt/,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends \
    # For development
    sudo \
    # rusb builds its own libusb but links against libudev for enumeration;
    # pkg-config lets the build find it.
    libudev-dev pkg-config

RUN groupadd -g $GID rust \
    && useradd -m -s /bin/bash -u $UID -g $GID rust \
    && echo 'rust ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers \
    && adduser rust plugdev

# The toolchain lives in the image; give the container user its own writable
# CARGO_HOME so cargo can update the registry.
ENV CARGO_HOME=/home/rust/.cargo
ENV PATH=$CARGO_HOME/bin:$PATH

USER rust

RUN rustup component add clippy rustfmt
