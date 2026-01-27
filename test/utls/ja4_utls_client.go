package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	utls "github.com/refraction-networking/utls"
)

const (
	serverAddr = "127.0.0.1:443"
	serverName = "localhost"

	tlsEmptyRenegotiationInfoSCSV uint16 = 0x00ff
	unknownCipherSuite            uint16 = 0x1234
)

func expectedCipherCount(spec *utls.ClientHelloSpec) int {
	count := 0
	for _, cs := range spec.CipherSuites {
		if cs == utls.GREASE_PLACEHOLDER {
			continue
		}
		count++
	}
	return count
}

func mutateSpec(mode string, spec *utls.ClientHelloSpec) error {
	switch mode {
	case "invalid":
		spec.CipherSuites = append(spec.CipherSuites, unknownCipherSuite)
		return nil
	case "scsv":
		for _, cs := range spec.CipherSuites {
			if cs == tlsEmptyRenegotiationInfoSCSV {
				return nil
			}
		}
		spec.CipherSuites = append(spec.CipherSuites, tlsEmptyRenegotiationInfoSCSV)
		return nil
	default:
		return fmt.Errorf("unknown mode: %s", mode)
	}
}

func main() {
	mode := flag.String("mode", "", "cipher mutation mode: invalid or scsv")
	flag.Parse()
	if *mode == "" {
		fmt.Fprintln(os.Stderr, "ERROR: --mode is required (invalid or scsv)")
		os.Exit(1)
	}

	conn, err := net.DialTimeout("tcp", serverAddr, 5*time.Second)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: dial failed: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	config := &utls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true,
	}

	spec, err := utls.UTLSIdToSpec(utls.HelloChrome_120)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: UTLSIdToSpec failed: %v\n", err)
		os.Exit(1)
	}

	if err := mutateSpec(*mode, &spec); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(1)
	}

	expectedCount := expectedCipherCount(&spec)

	uconn := utls.UClient(conn, config, utls.HelloCustom)
	if err := uconn.ApplyPreset(&spec); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: ApplyPreset failed: %v\n", err)
		os.Exit(1)
	}
	if err := uconn.Handshake(); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: TLS handshake failed: %v\n", err)
		os.Exit(1)
	}

	req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", serverName)
	if _, err := io.WriteString(uconn, req); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: write request failed: %v\n", err)
		os.Exit(1)
	}

	reader := bufio.NewReader(uconn)
	resp, err := http.ReadResponse(reader, &http.Request{Method: "GET"})
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: read response failed: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: read body failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("EXPECTED_CIPHER_COUNT=%d\n", expectedCount)
	fmt.Print(string(body))
}
