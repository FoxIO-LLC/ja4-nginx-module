# -------- Stage 1: Common base with packages --------
FROM alpine AS base

ARG DEBIAN_FRONTEND=noninteractive

RUN apk add --no-cache \
    gcc \
    libc-dev \
    make \
    openssl-dev \
    pcre-dev \
    zlib-dev \
    wget \
    patch \
    perl-dev \
    nghttp2-dev \
    nghttp3-dev \
    linux-headers

RUN adduser -D dswebuser

# -------- Stage 2: Precompiled sources for caching --------
FROM base AS build-cache

ARG NGINX_VERSION=1.25.0
ARG OPENSSL_VERSION=3.2.1

WORKDIR /tmp

# Download and extract
# Nginx source code
RUN wget https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz && \
    tar -zxf nginx-${NGINX_VERSION}.tar.gz
# OpenSSL source code
RUN wget https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz && \
    tar -zxf openssl-${OPENSSL_VERSION}.tar.gz

COPY src/config /tmp/ja4-nginx-module/src/config
COPY src/ngx_http_ssl_ja4_module.[ch] /tmp/ja4-nginx-module/src/
COPY patches/nginx.patch /tmp/ja4-nginx-module/patches/

WORKDIR /tmp/nginx-${NGINX_VERSION}
RUN patch -p1 < /tmp/ja4-nginx-module/patches/nginx.patch

RUN ./configure \
      --with-openssl=/tmp/openssl-${OPENSSL_VERSION} \
      --with-debug --with-compat \
      --add-module=/tmp/ja4-nginx-module/src \
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
RUN rm -rf /tmp/*

# Run Nginx in the foreground
CMD ["/etc/nginx/sbin/nginx", "-g", "daemon off;"]
