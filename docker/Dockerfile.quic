FROM alpine

# Define the version as a build argument for easy updates
ARG VERSION=v0.1.0-alpha
ARG NGINX_VERSION=1.25.0
RUN apk add --no-cache \
    gcc \
    libc-dev \
    make \
    openssl-dev \
    pcre-dev \
    zlib-dev \
    wget \
    patch

RUN adduser -D dswebuser

WORKDIR /tmp

# INSTALL NGINX
RUN wget https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz && \
    tar -zxvf nginx-${NGINX_VERSION}.tar.gz

WORKDIR /tmp/nginx-${NGINX_VERSION}

# JA4 patch - assumes patch name doesn't include version, adjust if it does
RUN wget https://github.com/FoxIO-LLC/ja4-nginx-module/releases/download/${VERSION}/nginx.patch && \
    patch -p1 < nginx.patch

# JA4 module
RUN wget https://github.com/FoxIO-LLC/ja4-nginx-module/releases/download/${VERSION}/ja4-nginx-module-${VERSION}.tar.gz && \
    tar -zxvf ja4-nginx-module-${VERSION}.tar.gz

# Build Nginx
# Assumes the extracted directory name matches the tarball's root directory name, adjust if necessary
RUN ./configure --with-debug --with-compat --add-module=/tmp/nginx-${NGINX_VERSION}/ja4-nginx-module-${VERSION}/src --with-http_ssl_module && \
    make && \
    make install

# Cleanup
WORKDIR /
RUN rm -rf /tmp/

# Link Nginx logs to stdout and stderr
RUN ln -sf /dev/stdout /usr/local/nginx/logs/access.log && \
    ln -sf /dev/stderr /usr/local/nginx/logs/error.log

# CMD directive to run Nginx in the foreground
CMD ["/usr/local/nginx/sbin/nginx", "-g", "daemon off;"]
