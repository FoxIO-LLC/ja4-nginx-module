import re
import subprocess
import pytest
from pathlib import Path

# Pinned curl image for reproducible TLS stack
CURL_IMG = "alpine/curl:8.14.1@sha256:4007cdf991c197c3412b5af737a916a894809273570b0c2bb93d295342fc23a2"

# URL for curl cases
URL = "https://localhost"

# Test matrix: (case_name, case_args)
CASES = [
    ("tls13_h2",   ["--http2", "--tls-max", "1.3"]),
    ("tls12_h11",  ["--http1.1", "--tls-max", "1.2"]),
    ("no_sni_ip",  []),  # IP literal to avoid SNI
    ("ech_alps",   ["--python-test"]),  # Test ECH and ALPS extensions together
    ("invalid_cipher_count", ["--go-invalid-cipher-test"]),  # Unknown cipher in list
]

EXPECTED_DIR = Path(__file__).parent / "testdata"
EXPECTED_DIR.mkdir(exist_ok=True)

def run_case(name: str, args: list[str]) -> str:
    """
    Run the selected case: curl in the pinned container,
    or a Python/Go test client.
    Capture stdout and return it as a string.
    """
    # Check if this is the Python test (ECH+ALPS)
    if args and args[0] == "--python-test":
        import sys
        test_script = Path(__file__).parent / "test_ech_alps.py"
        
        # Run the Python test script
        cmd = [sys.executable, str(test_script)]
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        return result.stdout

    # Go uTLS test for invalid cipher counting
    if args and args[0] == "--go-invalid-cipher-test":
        utls_dir = Path(__file__).parent / "utls"
        cmd = ["go", "run", "./invalid_cipher_count.go"]
        result = subprocess.run(
            cmd, check=True, capture_output=True, text=True, cwd=utls_dir
        )
        return result.stdout
    
    # Standard curl test
    if name == "no_sni_ip":
        curl_cmd = f"curl -k -sS https://127.0.0.1"
    else:
        curl_cmd = f"curl -k -sS {' '.join(args)} {URL}"

    cmd = [
        "docker", "run", "--rm", "--network", "host", CURL_IMG,
        "sh", "-lc", curl_cmd
    ]
    result = subprocess.run(cmd, check=True, capture_output=True, text=True)
    return result.stdout

@pytest.mark.parametrize("name,case_args", CASES)
def test_integration(name, case_args, request):
    output = run_case(name, case_args)
    print(f"\n=== Output for {name} ===\n{output}")

    if name == "invalid_cipher_count":
        lines = output.splitlines()
        expected_line = next((l for l in lines if l.startswith("EXPECTED_CIPHER_COUNT=")), None)
        assert expected_line is not None, "Missing EXPECTED_CIPHER_COUNT line"
        expected_count = int(expected_line.split("=", 1)[1])

        match = re.search(r"\bJA4:\s*([A-Za-z0-9_]+)", output)
        assert match is not None, f"Missing JA4 line in output:\n{output}"
        ja4 = match.group(1)
        assert len(ja4) >= 6, f"Unexpected JA4 string: {ja4!r}"
        actual_count = int(ja4[4:6])
        assert actual_count == expected_count, (
            f"Cipher count mismatch: expected {expected_count}, got {actual_count}"
        )
        return

    expected_path = EXPECTED_DIR / f"{name}.txt"
    if request.config.getoption("--record"):
        expected_path.write_text(output)
        print(f"[INFO] Recorded output for {name} to {expected_path}")
    else:
        assert expected_path.exists(), f"Missing golden file for {name}: {expected_path}"
        expected = expected_path.read_text()
        assert output == expected, f"Output mismatch for {name}"
