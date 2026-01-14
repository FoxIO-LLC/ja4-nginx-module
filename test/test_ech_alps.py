#!/usr/bin/env python3
"""
Test script for ECH and ALPS TLS extensions using curl_cffi.

This script uses curl_cffi to impersonate modern Chrome which natively
supports both ECH (0xfe0d) and ALPS (0x44cd) extensions.
"""

def main():
    """Run the test with curl_cffi."""
    import sys
    
    try:
        import curl_cffi.requests as requests
        
        # Make HTTPS request with Chrome impersonation
        # Modern Chrome versions include both ECH and ALPS extensions
        response = requests.get(
            "https://localhost",
            impersonate="chrome136",
            verify=False,  # Skip certificate verification for self-signed cert
            timeout=10
        )
        
        print(response.text, end='')
        
    except ImportError:
        print("ERROR: curl_cffi not installed. Install with: pip install curl_cffi", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
