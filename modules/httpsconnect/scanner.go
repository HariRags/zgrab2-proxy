// Package httpsconnect contains the zgrab2 Module implementation for HTTP CONNECT proxy detection.
//
// This module sends an HTTP CONNECT request to detect if a server is an HTTP/HTTPS proxy.
// It reports the response status code and headers to determine proxy support.
package httpsconnect

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/textproto"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/zmap/zcrypto/tls"

	"github.com/zmap/zgrab2"
)

// ScanResults is the output of the HTTP CONNECT proxy scan.
type ScanResults struct {
	// ConnectStatusCode is the HTTP status code returned from the CONNECT request
	ConnectStatusCode int `json:"connect_status_code,omitempty"`

	// ConnectStatusLine is the full status line (e.g., "HTTP/1.1 200 Connection established")
	ConnectStatusLine string `json:"connect_status_line,omitempty"`

	// ProxySupported indicates if the server appears to support HTTP CONNECT
	ProxySupported bool `json:"proxy_supported"`

	// Headers contains the response headers from the proxy
	Headers map[string][]string `json:"headers,omitempty"`

	// RawResponse contains the raw response data for debugging
	RawResponse string `json:"raw_response,omitempty"`

	// PageStatusCode is the HTTP status code from the page fetch request
	PageStatusCode int `json:"page_status_code,omitempty"`

	// PageStatusLine is the full status line from the page fetch
	PageStatusLine string `json:"page_status_line,omitempty"`

	// PageHeaders contains the response headers from the fetched page
	PageHeaders map[string][]string `json:"page_headers,omitempty"`

	// PageBody contains the content of the fetched page
	PageBody string `json:"page_body,omitempty"`

	// PageBodyTruncated indicates if the page body was truncated due to size limits
	PageBodyTruncated bool `json:"page_body_truncated,omitempty"`

	// Error contains any error message if the scan partially failed
	Error string `json:"error,omitempty"`
}

// Flags are the HTTP CONNECT proxy-specific command-line flags.
type Flags struct {
	zgrab2.BaseFlags

	// ConnectHost is the host to use in the CONNECT request
	ConnectHost string `long:"connect-host" default:"example.com" description:"Host to use in CONNECT request"`

	// ConnectPort is the port to use in the CONNECT request
	ConnectPort int `long:"connect-port" default:"443" description:"Port to use in CONNECT request"`

	// UserAgent is the User-Agent header to send
	UserAgent string `long:"user-agent" default:"curl/7.81.0" description:"User-Agent header value"`

	// MaxResponseSize is the maximum response size to read
	MaxResponseSize int `long:"max-response-size" default:"4096" description:"Maximum response size to read in bytes"`

	// IncludeRawResponse includes the raw response in the output
	IncludeRawResponse bool `long:"include-raw-response" description:"Include raw response in output"`

	// FetchPage enables fetching a page through the tunnel after CONNECT
	FetchPage bool `long:"fetch-page" description:"Fetch a page through the tunnel after successful CONNECT"`

	// PagePath is the path to fetch from the target server
	PagePath string `long:"page-path" default:"/" description:"Path to fetch from target server"`

	// MaxPageSize is the maximum page content size to read
	MaxPageSize int `long:"max-page-size" default:"65536" description:"Maximum page content size to read in bytes"`

	// UseHTTPS determines whether to use HTTPS for the page fetch
	UseHTTPS bool `long:"use-https" description:"Use HTTPS for page fetch (default: true if connect port is 443)"`
}

// Module implements the zgrab2.Module interface.
type Module struct {
}

// Scanner implements the zgrab2.Scanner interface, and holds the state
// for a single scan.
type Scanner struct {
	config            *Flags
	dialerGroupConfig *zgrab2.DialerGroupConfig
}

// RegisterModule registers the httpsconnect zgrab2 module.
func RegisterModule() {
	var module Module
	_, err := zgrab2.AddCommand("httpsconnect", "HTTP CONNECT Proxy Detection", module.Description(), 8080, &module)
	if err != nil {
		log.Fatal(err)
	}
}

// NewFlags returns the default flags object to be filled in with the
// command-line arguments.
func (m *Module) NewFlags() interface{} {
	return new(Flags)
}

// NewScanner returns a new Scanner instance.
func (m *Module) NewScanner() zgrab2.Scanner {
	return new(Scanner)
}

// Description returns an overview of this module.
func (m *Module) Description() string {
	return "Send an HTTP CONNECT request to detect if the target is an HTTPS proxy server"
}

// Validate flags
func (f *Flags) Validate(_ []string) (err error) {
	if f.ConnectPort <= 0 || f.ConnectPort > 65535 {
		return fmt.Errorf("connect-port must be between 1 and 65535")
	}
	if f.MaxPageSize <= 0 {
		f.MaxPageSize = 65536
	}
	// Auto-enable HTTPS if port 443
	if f.ConnectPort == 443 && !f.UseHTTPS {
		f.UseHTTPS = true
	}
	return nil
}

// Help returns this module's help string.
func (f *Flags) Help() string {
	return "This module sends an HTTP CONNECT request to detect HTTPS proxy servers. " +
		"A successful response (2xx status code) indicates the server supports HTTP CONNECT tunneling."
}

// Protocol returns the protocol identifier for the scanner.
func (scanner *Scanner) Protocol() string {
	return "httpproxy"
}

func (scanner *Scanner) GetDialerGroupConfig() *zgrab2.DialerGroupConfig {
	return scanner.dialerGroupConfig
}

// Init initializes the Scanner instance with the flags from the command line.
func (scanner *Scanner) Init(flags zgrab2.ScanFlags) error {
	f, _ := flags.(*Flags)
	scanner.config = f
	scanner.dialerGroupConfig = &zgrab2.DialerGroupConfig{
		TransportAgnosticDialerProtocol: zgrab2.TransportTCP,
		BaseFlags:                       &f.BaseFlags,
	}
	return nil
}

// InitPerSender does nothing in this module.
func (scanner *Scanner) InitPerSender(senderID int) error {
	return nil
}

// GetName returns the configured name for the Scanner.
func (scanner *Scanner) GetName() string {
	return scanner.config.Name
}

// GetTrigger returns the Trigger defined in the Flags.
func (scanner *Scanner) GetTrigger() string {
	return scanner.config.Trigger
}

// GetScanMetadata returns any metadata on the scan itself from this module.
func (scanner *Scanner) GetScanMetadata() any {
	return nil
}

// buildConnectRequest builds the HTTP CONNECT request bytes.
func (scanner *Scanner) buildConnectRequest() []byte {
	target := fmt.Sprintf("%s:%d", scanner.config.ConnectHost, scanner.config.ConnectPort)
	request := fmt.Sprintf(
		"CONNECT %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"User-Agent: %s\r\n"+
			"Proxy-Connection: Keep-Alive\r\n"+
			"\r\n",
		target, target, scanner.config.UserAgent)
	return []byte(request)
}

// buildHTTPRequest builds the HTTP GET request bytes for fetching the page.
func (scanner *Scanner) buildHTTPRequest() []byte {
	request := fmt.Sprintf(
		"GET %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"User-Agent: %s\r\n"+
			"Accept: */*\r\n"+
			"\r\n",
		scanner.config.PagePath, scanner.config.ConnectHost, scanner.config.UserAgent)
	return []byte(request)
}

// parseHTTPResponse parses the HTTP response from the proxy.
func parseHTTPResponse(data []byte) (statusCode int, statusLine string, headers map[string][]string, err error) {
	reader := bufio.NewReader(strings.NewReader(string(data)))
	tp := textproto.NewReader(reader)

	// Read status line
	statusLine, err = tp.ReadLine()
	if err != nil {
		return 0, "", nil, fmt.Errorf("failed to read status line: %w", err)
	}

	// Parse status code from status line (e.g., "HTTP/1.1 200 Connection established")
	parts := strings.SplitN(statusLine, " ", 3)
	if len(parts) < 2 {
		return 0, statusLine, nil, fmt.Errorf("malformed status line: %s", statusLine)
	}

	statusCode, err = strconv.Atoi(parts[1])
	if err != nil {
		return 0, statusLine, nil, fmt.Errorf("invalid status code: %s", parts[1])
	}

	// Read headers
	headers, err = tp.ReadMIMEHeader()
	if err != nil && err.Error() != "EOF" {
		// It's okay if we hit EOF after headers, some proxies send minimal responses
		headers = make(map[string][]string)
	}

	return statusCode, statusLine, headers, nil
}

// fetchPageContent fetches the page content through the established tunnel.
func (scanner *Scanner) fetchPageContent(ctx context.Context, conn net.Conn) (statusCode int, statusLine string, headers map[string][]string, body string, truncated bool, err error) {
	// If HTTPS is enabled, wrap the connection with TLS
	var pageConn net.Conn = conn
	if scanner.config.UseHTTPS {
		tlsConfig := &tls.Config{
			ServerName:         scanner.config.ConnectHost,
			InsecureSkipVerify: true, // For scanning purposes
		}
		pageConn = tls.Client(conn, tlsConfig)
	}

	// Set deadline if context has one
	if deadline, ok := ctx.Deadline(); ok {
		if err := pageConn.SetWriteDeadline(deadline); err != nil {
			return 0, "", nil, "", false, fmt.Errorf("failed to set write deadline: %w", err)
		}
		if err := pageConn.SetReadDeadline(deadline); err != nil {
			return 0, "", nil, "", false, fmt.Errorf("failed to set read deadline: %w", err)
		}
	}

	// Send HTTP GET request
	request := scanner.buildHTTPRequest()
	_, err = pageConn.Write(request)
	if err != nil {
		return 0, "", nil, "", false, fmt.Errorf("failed to send HTTP request: %w", err)
	}

	// Read response
	response := make([]byte, scanner.config.MaxPageSize)
	n, err := pageConn.Read(response)
	if err != nil && err != io.EOF && n == 0 {
		return 0, "", nil, "", false, fmt.Errorf("failed to read HTTP response: %w", err)
	}

	responseData := response[:n]

	// Parse response
	reader := bufio.NewReader(strings.NewReader(string(responseData)))
	tp := textproto.NewReader(reader)

	// Read status line
	statusLine, err = tp.ReadLine()
	if err != nil {
		return 0, "", nil, "", false, fmt.Errorf("failed to read HTTP status line: %w", err)
	}

	// Parse status code
	parts := strings.SplitN(statusLine, " ", 3)
	if len(parts) < 2 {
		return 0, statusLine, nil, "", false, fmt.Errorf("malformed HTTP status line: %s", statusLine)
	}

	statusCode, err = strconv.Atoi(parts[1])
	if err != nil {
		return 0, statusLine, nil, "", false, fmt.Errorf("invalid HTTP status code: %s", parts[1])
	}

	// Read headers
	headers, err = tp.ReadMIMEHeader()
	if err != nil && err.Error() != "EOF" {
		headers = make(map[string][]string)
	}

	// Read body
	remainingData := string(responseData)
	// Find where headers end (look for \r\n\r\n)
	headerEnd := strings.Index(remainingData, "\r\n\r\n")
	if headerEnd != -1 {
		body = remainingData[headerEnd+4:]
	} else {
		body = ""
	}
	truncated = n >= scanner.config.MaxPageSize

	return statusCode, statusLine, headers, body, truncated, nil
}

// Scan performs the HTTP CONNECT proxy detection scan.
func (scanner *Scanner) Scan(ctx context.Context, dialGroup *zgrab2.DialerGroup, target *zgrab2.ScanTarget) (zgrab2.ScanStatus, any, error) {
	var results ScanResults

	// Connect to target
	conn, err := dialGroup.Dial(ctx, target)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, fmt.Errorf("failed to connect: %w", err)
	}
	defer zgrab2.CloseConnAndHandleError(conn)

	// Send CONNECT request
	request := scanner.buildConnectRequest()
	_, err = conn.Write(request)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), &results, fmt.Errorf("failed to send CONNECT request: %w", err)
	}

	// Read response
	respBuf := make([]byte, scanner.config.MaxResponseSize)
	n, err := readWithContext(ctx, conn, respBuf)
	if err != nil && n == 0 {
		return zgrab2.TryGetScanStatus(err), &results, fmt.Errorf("failed to read response: %w", err)
	}

	responseData := respBuf[:n]

	if scanner.config.IncludeRawResponse {
		results.RawResponse = string(responseData)
	}

	// Parse HTTP response
	statusCode, statusLine, headers, parseErr := parseHTTPResponse(responseData)
	if parseErr != nil {
		results.Error = parseErr.Error()
		// Still return what we have, might be useful for analysis
		if scanner.config.IncludeRawResponse && results.RawResponse == "" {
			results.RawResponse = string(responseData)
		}
		return zgrab2.SCAN_PROTOCOL_ERROR, &results, parseErr
	}

	results.ConnectStatusCode = statusCode
	results.ConnectStatusLine = statusLine
	results.Headers = headers

	// Determine if proxy is supported based on status code
	// 2xx status codes indicate success
	// 407 indicates proxy authentication required (proxy exists but needs auth)
	results.ProxySupported = (statusCode >= 200 && statusCode < 400) || statusCode == 407 || statusCode == 403 || statusCode == 404

	// If CONNECT was successful and page fetching is enabled, fetch the page
	if scanner.config.FetchPage && statusCode >= 200 && statusCode < 300 {
		pageStatusCode, pageStatusLine, pageHeaders, pageBody, pageTruncated, pageErr := scanner.fetchPageContent(ctx, conn)
		if pageErr != nil {
			if results.Error == "" {
				results.Error = fmt.Sprintf("page fetch failed: %v", pageErr)
			} else {
				results.Error += fmt.Sprintf("; page fetch failed: %v", pageErr)
			}
		} else {
			results.PageStatusCode = pageStatusCode
			results.PageStatusLine = pageStatusLine
			results.PageHeaders = pageHeaders
			results.PageBody = pageBody
			results.PageBodyTruncated = pageTruncated
		}
	}

	return zgrab2.SCAN_SUCCESS, &results, nil
}

// readWithContext reads from connection with context deadline support.
func readWithContext(ctx context.Context, conn net.Conn, buf []byte) (int, error) {
	// Set deadline if context has one
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetReadDeadline(deadline); err != nil {
			return 0, err
		}
	}

	return conn.Read(buf)
}
