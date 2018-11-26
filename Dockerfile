# docker build -f Dockerfile -t crdt-tp-python:local .

# -------------=== crdt-tp-python build ===-------------

FROM ubuntu:bionic

# Set the locale for modern unicode python: ubuntu image defaults to ASCII
ENV LANG C.UTF-8
ENV LC_ALL C.UTF-8

# Pip requires a "falsy" value to disable building the cache
# https://pip.pypa.io/en/stable/user_guide/#configuration
ENV PIP_NO_CACHE_DIR false

RUN apt-get update && apt-get install -y -q \
        libsecp256k1-0 \
        libsecp256k1-dev \
        pkg-config \
        python3 \
        python3-pip \
    && rm -rf /var/lib/apt/lists/*

COPY Pipfile Pipfile.lock ./

RUN pip3 install --upgrade \
        pipenv \
    && pipenv install --system --deploy

COPY crdt-tp-python ./crdt-tp-python
