import socket
import ssl

import pytest

HOST = "localhost"
PORT = 443


def fetch_response(alpn: str | None) -> str:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if alpn is not None:
        ctx.set_alpn_protocols([alpn, "http/1.1"])

    with socket.create_connection((HOST, PORT), timeout=5) as sock:
        with ctx.wrap_socket(sock, server_hostname=HOST) as ssock:
            req = b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
            ssock.sendall(req)
            data = b""
            while True:
                chunk = ssock.recv(4096)
                if not chunk:
                    break
                data += chunk

    text = data.decode("utf-8", "replace")
    parts = text.split("\r\n\r\n", 1)
    return parts[1] if len(parts) == 2 else text


def extract_field(body: str, label: str) -> str:
    for line in body.splitlines():
        line = line.strip()
        if line.startswith(f"{label}:"):
            return line.split(":", 1)[1].strip()
    raise AssertionError(f"Missing {label} in response body")


CASES = [
    ("no_alpn", None, "00"),
    ("one_char", "h", "hh"),
    ("char_space", "h ", "60"),
    ("space_char", " h", "28"),
    ("space_space", "  ", "20"),
    ("non_alnum", "--", "2d"),
]


@pytest.mark.parametrize("name,alpn,expected", CASES)
def test_ja4_alpn_values(name: str, alpn: str | None, expected: str) -> None:
    body = fetch_response(alpn)
    ja4 = extract_field(body, "JA4")
    ja4_string = extract_field(body, "JA4 String")
    ja4one = extract_field(body, "JA4one")

    assert ja4.split("_", 1)[0][-2:] == expected
    assert ja4_string.split("_", 1)[0][-2:] == expected
    assert ja4one.split("_", 1)[0][-2:] == expected
