# Stage 1: Build
FROM debian:bookworm-slim AS build

# Set environment variables for non-interactive installation and versions
ENV DEBIAN_FRONTEND=noninteractive \
    ARGUS_VERSION=5.0.0 \
    CLIENTS_VERSION=5.0.0

# Install dependencies
RUN apt-get update && \
    apt-get install -y gcc make flex bison zlib1g-dev libpcap-dev wget

WORKDIR /argus

# Download and extract source code from GitHub releases
RUN wget https://github.com/openargus/clients/archive/refs/tags/v${CLIENTS_VERSION}.tar.gz -O clients-${CLIENTS_VERSION}.tar.gz && \
    tar -xvf clients-${CLIENTS_VERSION}.tar.gz && \
    wget https://github.com/openargus/argus/archive/refs/tags/v${ARGUS_VERSION}.tar.gz -O argus-${ARGUS_VERSION}.tar.gz && \
    tar -xvf argus-${ARGUS_VERSION}.tar.gz

# Build and install argus and clients
RUN cd clients-${CLIENTS_VERSION} && \
    LIBS="-lz" ./configure && \
    make && \
    make install && \
    cd ../argus-${ARGUS_VERSION} && \
    LIBS="-lz" ./configure && \
    make && \
    make install

# Stage 2: Runtime
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && \
    apt-get install -y zlib1g libpcap0.8 libtirpc3 && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /argus

# Copy the built files from the build stage
COPY --from=build /usr/local /usr/local

# Set a default command (optional)
CMD ["bash"]
