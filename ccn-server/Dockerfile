# Build from the project root directory context...
# docker build -f ccn-server/Dockerfile -t ccn-server:local .

# -------------=== ccn-server deployment image ===-------------

FROM hyperledger/sawtooth-shell:1.0

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

COPY ccn-server/Pipfile ccn-server/Pipfile.lock ./ccn-server/

# Install and later run in a virtualenv to avoid conflicting with sawtooth python components.
RUN pip3 install --upgrade pipenv \
    && cd ccn-server \
    && pipenv install --deploy

ENV PYTHONPATH "/ccn-server"

# Add the python protocol dependencies
# TODO(matt9j) Eventually move to a more structured language independent protocol like protobuf
COPY asterales-protocol/asterales_protocol/ ./ccn-server/asterales_protocol

COPY ccn-server/ ./ccn-server
