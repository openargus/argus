# Stage 1: Build
FROM debian:bookworm-slim AS build

# Set environment variables for non-interactive installation and versions
ENV DEBIAN_FRONTEND=noninteractive \
    ARGUS_VERSION=5.0.0 \
    CLIENTS_VERSION=5.0.0

# Install dependencies
RUN apt-get update && \
    apt-get install -y gcc make flex bison zlib1g-dev libpcap-dev

WORKDIR /argus

# Copy and extract source code
COPY argus-${ARGUS_VERSION}.tar.gz clients-${CLIENTS_VERSION}.tar.gz ./

# Build and install argus and clients
RUN tar -xzf clients-${CLIENTS_VERSION}.tar.gz && \
    cd clients-${CLIENTS_VERSION} && \
    LIBS="-lz" ./configure && \
    make && \
    make install && \
    cd .. && \
    tar -xzf argus-${ARGUS_VERSION}.tar.gz && \
    cd argus-${ARGUS_VERSION} && \
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
