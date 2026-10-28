#!/usr/bin/env bash
# Smoke test for the Docker image started by `docker compose up -d`.
#
# Checks that the image's nginx accepts the mounted configuration and that
# the module reports fingerprints at runtime. Exact fingerprints are covered
# by test/test-nginx; here the host curl's TLS stack varies, so only the
# shape of each value is checked.
set -euo pipefail

fail() {
	printf 'docker-smoke: %s\n' "$*" >&2
	exit 1
}

docker compose exec -T ja4-nginx /etc/nginx/sbin/nginx -t

# Retry until nginx accepts TLS connections.
body="$(curl -fsSk --retry 30 --retry-delay 1 --retry-all-errors https://localhost/)"
printf '%s\n' "${body}"

# Prints the value of a "Label: value" line of nginx_utils/nginx.conf's body.
field() {
	printf '%s\n' "${body}" | sed -n "s/^ *$1: //p"
}

expect() {
	local label="$1" regex="$2" value
	value="$(field "${label}")"
	[[ "${value}" =~ ${regex} ]] \
		|| fail "${label} '${value}' does not match ${regex}"
}

# localhost sends SNI (d); nginx_utils/nginx.conf serves only HTTP/1.1.
expect 'JA4' '^t1[23]d[0-9]{4}(h1|h2)_[0-9a-f]{12}_[0-9a-f]{12}$'
expect 'JA4 String' '^t1[23]d[0-9]{4}(h1|h2)_[0-9a-f,]+_[0-9a-f,]+_[0-9a-f,]+$'
expect 'JA4one' '^t1[23]d[0-9]{4}(h1|h2)_[0-9a-f]{12}_[0-9a-f]{12}$'
expect 'JA4H' '^ge11nn[0-9]{2}0000_[0-9a-f]{12}_0{12}_0{12}$'
expect 'JA4H String' '^ge11nn[0-9]{2}0000_Host,'
expect 'JA4L' '^0_0_64$'
# Capture is off in nginx_utils/nginx.conf; JA4S and JA4X are not implemented.
for label in 'JA4S' 'JA4S String' 'JA4T' 'JA4TS' 'JA4X'; do
	expect "${label}" '^$'
done

[[ "$(field 'JA4 String' | cut -d_ -f1)" == "$(field 'JA4' | cut -d_ -f1)" ]] \
	|| fail 'JA4 and JA4 String differ in their first part'

[[ "$(curl -fsS http://localhost/)" == ok ]] \
	|| fail 'plain HTTP server did not return ok'

printf 'docker-smoke: ok\n'
