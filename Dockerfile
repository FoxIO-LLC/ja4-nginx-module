# -------- Stage 1: Common base with packages --------
FROM alpine AS base

ARG DEBIAN_FRONTEND=noninteractive

# No openssl-dev: nginx builds against the OpenSSL from the openssl stage,
# and system headers would shadow it.
RUN apk add --no-cache \
    gcc \
    libc-dev \
    make \
    pcre-dev \
    zlib-dev \
    wget \
    patch \
    perl-dev \
    nghttp2-dev \
    nghttp3-dev \
    linux-headers

RUN adduser -D dswebuser

# -------- Stage 2: OpenSSL --------
# Depends only on OPENSSL_VERSION, so CI reuses it from the layer cache.
# The options match what nginx's --with-openssl would pass.
FROM base AS openssl

ARG OPENSSL_VERSION=4.0.0

WORKDIR /tmp
RUN wget https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz && \
    tar -zxf openssl-${OPENSSL_VERSION}.tar.gz

WORKDIR /tmp/openssl-${OPENSSL_VERSION}
RUN ./config --prefix=/opt/openssl --libdir=lib \
      no-shared no-threads no-tests no-docs && \
    make -j$(nproc) && \
    make install_sw

# -------- Stage 3: nginx with the module --------
FROM base AS final

ARG NGINX_VERSION=1.30.0

COPY --from=openssl /opt/openssl /opt/openssl

WORKDIR /tmp
RUN wget https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz && \
    tar -zxf nginx-${NGINX_VERSION}.tar.gz

COPY . /tmp/ja4-nginx-module
WORKDIR /tmp/nginx-${NGINX_VERSION}
RUN patch -p1 < /tmp/ja4-nginx-module/patches/nginx-tcp-save-syn.patch && \
    patch -p1 < /tmp/ja4-nginx-module/patches/nginx.patch

# OpenSSL is static (no-shared), so the binary has no runtime dependency
# on /opt/openssl.
RUN ./configure \
      --with-cc-opt="-I/opt/openssl/include" \
      --with-ld-opt="-L/opt/openssl/lib" \
      --with-debug --with-compat \
      --add-module=/tmp/ja4-nginx-module \
      --with-http_ssl_module \
      --with-http_v2_module \
      --with-http_v3_module \
      --prefix=/etc/nginx && \
    make -j$(nproc) && \
    make install

# Link logs
RUN ln -sf /dev/stdout /etc/nginx/logs/access.log && \
    ln -sf /dev/stderr /etc/nginx/logs/error.log

# Clean up
WORKDIR /
RUN rm -rf /tmp/* /opt/openssl

# Run Nginx in the foreground
CMD ["/etc/nginx/sbin/nginx", "-g", "daemon off;"]
