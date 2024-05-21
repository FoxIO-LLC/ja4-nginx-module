FROM alpine

# Define the version as a build argument for easy updates
ARG NGINX_VERSION=1.24.0
ARG OPENSSL_VERSION=3.2.1
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
    linux-headers


RUN adduser -D dswebuser

WORKDIR /tmp

COPY . ./ja4-nginx-module

# INSTALL NGINX
RUN wget https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz && \
    tar -zxvf nginx-${NGINX_VERSION}.tar.gz

# INSTALL OpenSSL
RUN wget https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz && \
    tar -zxvf openssl-${OPENSSL_VERSION}.tar.gz

# patch openssl
WORKDIR /tmp/openssl-${OPENSSL_VERSION}

RUN patch -p1 < /tmp/ja4-nginx-module/patches/openssl.patch

# patch nginx
WORKDIR /tmp/nginx-${NGINX_VERSION}

RUN patch -p1 < /tmp/ja4-nginx-module/patches/nginx.patch

# Build Nginx
RUN ./configure --with-openssl=/tmp/openssl-${OPENSSL_VERSION} --with-debug --with-compat --add-module=/tmp/ja4-nginx-module/src --with-http_ssl_module --prefix=/etc/nginx && \
    make && \
    make install

# Cleanup
WORKDIR /
RUN rm -rf /tmp/

# Link Nginx logs to stdout and stderr
RUN ln -sf /dev/stdout /etc/nginx/logs/access.log && \
    ln -sf /dev/stderr /etc/nginx/logs/error.log

# CMD directive to run Nginx in the foreground
CMD ["/etc/nginx/sbin/nginx", "-g", "daemon off;"]
