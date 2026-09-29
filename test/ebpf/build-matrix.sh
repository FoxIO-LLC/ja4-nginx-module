#!/bin/sh
# Compile production builds independently: HTTP, HTTP+stream, and without the addon.
set -eu
archive=$(realpath "${1:?usage: build-matrix.sh nginx.tar.gz output-directory}")
out=${2:?output directory required}
repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
mkdir -p "$out"
out=$(realpath "$out")
for mode in http combined disabled; do
    dest="$out/$mode"
    mkdir "$dest"
    tar -xzf "$archive" --strip-components=1 -C "$dest"
    (
        cd "$dest"
        patch -p1 < "$repo/patches/nginx.patch"
        patch -p1 < "$repo/patches/nginx-tcp-save-syn.patch"
        patch -p1 < "$repo/patches/nginx-tcp-save-synack.patch"
        set -- --with-debug
        case "$mode" in
            http) set -- "$@" --with-http_ssl_module --add-module="$repo" ;;
            *) set -- "$@" --with-http_ssl_module --with-stream --with-stream_ssl_module --add-module="$repo" ;;
        esac
        if [ "$mode" != disabled ]; then
            set -- "$@" --add-module="$repo/ebpf"
        fi
        ./configure "$@"
        make -j"${JOBS:-2}"
        mkdir -p logs
        if [ "$mode" = disabled ]; then
            printf 'events {} http { tcp_save_synack off; server { listen 127.0.0.1:18080; return 200 "[$upstream_ja4ts]"; } }\n' > smoke.conf
        else
            printf 'events {} http { tcp_save_synack on; server { listen 127.0.0.1:18080; return 200 "[$upstream_ja4ts]"; } }\n' > smoke.conf
        fi
        ./objs/nginx -t -p "$dest" -c smoke.conf
        if [ "$mode" = disabled ]; then
            sed 's/tcp_save_synack off/tcp_save_synack on/' smoke.conf > unsupported.conf
            if ./objs/nginx -t -p "$dest" -c unsupported.conf > unsupported.log 2>&1; then
                echo 'capture-enabled configuration incorrectly accepted without the addon' >&2
                exit 1
            fi
            grep -q 'requires the optional ebpf core module' unsupported.log
        fi
    ) > "$out/$mode.log" 2>&1 || { cat "$out/$mode.log"; exit 1; }
    echo "PASS production $mode build and configuration"
done
