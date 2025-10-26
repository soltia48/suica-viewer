# syntax=docker/dockerfile:1

FROM python:3.14-bookworm

ARG UID=1000
ARG GID=1000

RUN --mount=type=cache,target=/var/lib/apt/,sharing=locked \
    --mount=type=cache,target=/var/cache/apt/,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends \
    # For development
    sudo \
    # For running
    libusb-1.0.0 fonts-dejavu-core fonts-freefont-ttf fonts-noto-cjk fonts-noto-color-emoji

RUN groupadd -g $GID python \
    && useradd -m -s /bin/bash -u $UID -g $GID python \
    && echo 'python ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers \
    && sudo adduser python plugdev

USER python

# Install Poetry
RUN curl -sSL https://install.python-poetry.org | python3 -
