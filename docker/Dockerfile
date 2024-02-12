FROM alpine

RUN apk add --no-cache \
    gcc \
    libc-dev \
    make \
    openssl-dev \
    pcre-dev \
    zlib-dev \
    wget \
    patch

# TODO: INSTALL MOD-SECURITY LIB

RUN adduser -D dswebuser

WORKDIR /tmp

# INSTALL NGINX
RUN wget https://nginx.org/download/nginx-1.25.0.tar.gz && \
    tar -zxvf nginx-1.25.0.tar.gz

WORKDIR /tmp/nginx-1.25.0

# INSTALL JA4
RUN wget https://github.com/FoxIO-LLC/ja4-plus-nginx/releases/download/v0.2.1-alpha/nginx.patch
RUN patch -p1 < nginx.patch

RUN wget https://github.com/FoxIO-LLC/ja4-plus-nginx/releases/download/v0.2.0-alpha/ja4-plus-nginx-v0.1.0-alpha.tar.gz && \
    tar -zxvf ja4-plus-nginx-v0.1.0-alpha.tar.gz

# TODO: INSTALL MOD-SECURITY MODULE


# Build Nginx
RUN ./configure --with-debug --with-compat --add-module=/tmp/nginx-1.25.0/ja4-plus-nginx-v0.1.0-alpha/src --with-http_ssl_module && \
    make && \
    make install

# Cleanup
WORKDIR /
RUN rm -rf /tmp/nginx-1.25.0 /tmp/nginx-1.25.0.tar.gz
RUN rm -rf /tmp/ja4-plus-nginx-v0.1.0-alpha /tmp/ja4-plus-nginx-v0.1.0-alpha.tar.gz


# Redirect Nginx logs to stdout and stderr
RUN ln -sf /dev/stdout /usr/local/nginx/logs/access.log \
    && ln -sf /dev/stderr /usr/local/nginx/logs/error.log

# CMD directive to run Nginx in the foreground
CMD ["/usr/local/nginx/sbin/nginx", "-g", "daemon off;"]
