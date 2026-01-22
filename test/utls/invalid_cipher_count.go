package main

import (
	"bufio"
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
)

func main() {
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

	// Add an unknown (non-GREASE) cipher suite to the end of the list.
	spec.CipherSuites = append(spec.CipherSuites, uint16(0x1234))

	expectedCount := 0
	for _, cs := range spec.CipherSuites {
		if cs == utls.GREASE_PLACEHOLDER {
			continue
		}
		expectedCount++
	}

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
