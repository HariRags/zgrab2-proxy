// Package httpproxy contains the zgrab2 Module implementation for HTTP proxy GET detection.
//
// This module sends an HTTP GET request through a proxy (like curl -x) to detect if a server
// is an HTTP proxy. It uses an absolute URL in the request line, which is how HTTP proxies
// expect requests to be formatted.
package httpproxy

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/textproto"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/zmap/zgrab2"
)

// ScanResults is the output of the HTTP proxy GET scan.
type ScanResults struct {
	// StatusCode is the HTTP status code returned from the proxy request
	StatusCode int `json:"status_code,omitempty"`

	// StatusLine is the full status line (e.g., "HTTP/1.1 200 OK")
	StatusLine string `json:"status_line,omitempty"`

	// ProxySupported indicates if the server appears to support HTTP proxy requests
	ProxySupported bool `json:"proxy_supported"`

	// Headers contains the response headers from the proxy
	Headers map[string][]string `json:"headers,omitempty"`

	// Body contains the response body (truncated to MaxBodySize)
	Body string `json:"body,omitempty"`

	// BodyLength is the length of the body received
	BodyLength int `json:"body_length,omitempty"`

	// RawResponse contains the raw response data for debugging
	RawResponse string `json:"raw_response,omitempty"`

	// Error contains any error message if the scan partially failed
	Error string `json:"error,omitempty"`
}

// Flags are the HTTP proxy-specific command-line flags.
type Flags struct {
	zgrab2.BaseFlags

	// TargetURL is the URL to request through the proxy
	TargetURL string `long:"target-url" default:"http://example.com/" description:"URL to request through the proxy"`

	// Method is the HTTP method to use
	Method string `long:"method" default:"GET" description:"HTTP method to use (GET, HEAD, etc.)"`

	// UserAgent is the User-Agent header to send
	UserAgent string `long:"user-agent" default:"curl/7.81.0" description:"User-Agent header value"`

	// MaxResponseSize is the maximum response size to read
	MaxResponseSize int `long:"max-response-size" default:"8192" description:"Maximum response size to read in bytes"`

	// MaxBodySize is the maximum body size to include in results
	MaxBodySize int `long:"max-body-size" default:"1024" description:"Maximum body size to include in results"`

	// IncludeRawResponse includes the raw response in the output
	IncludeRawResponse bool `long:"include-raw-response" description:"Include raw response in output"`

	// IncludeBody includes the response body in the output
	IncludeBody bool `long:"include-body" description:"Include response body in output"`
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

// RegisterModule registers the httpproxy zgrab2 module.
func RegisterModule() {
	var module Module
	_, err := zgrab2.AddCommand("httpproxy", "HTTP Proxy GET Detection", module.Description(), 8080, &module)
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
	return "Send an HTTP GET request through a proxy (like curl -x) to detect HTTP proxy servers"
}

// Validate flags
func (f *Flags) Validate(_ []string) (err error) {
	if !strings.HasPrefix(f.TargetURL, "http://") {
		return fmt.Errorf("target-url must start with http:// (HTTPS requires CONNECT method, use httpsconnect module)")
	}
	return nil
}

// Help returns this module's help string.
func (f *Flags) Help() string {
	return "This module sends an HTTP request through a proxy server (like curl -x). " +
		"It uses an absolute URL in the request line, which is how HTTP proxies expect requests. " +
		"For HTTPS tunneling (CONNECT method), use the httpsconnect module instead."
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

// extractHostFromURL extracts the host from a URL for the Host header.
func extractHostFromURL(url string) string {
	// Remove http://
	host := strings.TrimPrefix(url, "http://")
	// Remove path
	if idx := strings.Index(host, "/"); idx != -1 {
		host = host[:idx]
	}
	return host
}

// buildProxyRequest builds the HTTP proxy GET request bytes.
func (scanner *Scanner) buildProxyRequest() []byte {
	host := extractHostFromURL(scanner.config.TargetURL)
	request := fmt.Sprintf(
		"%s %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"User-Agent: %s\r\n"+
			"Proxy-Connection: Keep-Alive\r\n"+
			"Accept: */*\r\n"+
			"\r\n",
		scanner.config.Method, scanner.config.TargetURL, host, scanner.config.UserAgent)
	return []byte(request)
}

// parseHTTPResponse parses the HTTP response from the proxy.
func parseHTTPResponse(data []byte) (statusCode int, statusLine string, headers map[string][]string, bodyStart int, err error) {
	dataStr := string(data)
	reader := bufio.NewReader(strings.NewReader(dataStr))
	tp := textproto.NewReader(reader)

	// Read status line
	statusLine, err = tp.ReadLine()
	if err != nil {
		return 0, "", nil, 0, fmt.Errorf("failed to read status line: %w", err)
	}

	// Parse status code from status line (e.g., "HTTP/1.1 200 OK")
	parts := strings.SplitN(statusLine, " ", 3)
	if len(parts) < 2 {
		return 0, statusLine, nil, 0, fmt.Errorf("malformed status line: %s", statusLine)
	}

	statusCode, err = strconv.Atoi(parts[1])
	if err != nil {
		return 0, statusLine, nil, 0, fmt.Errorf("invalid status code: %s", parts[1])
	}

	// Read headers
	headers, err = tp.ReadMIMEHeader()
	if err != nil && err.Error() != "EOF" {
		// It's okay if we hit EOF after headers
		headers = make(map[string][]string)
	}

	// Find where the body starts (after \r\n\r\n)
	headerEnd := strings.Index(dataStr, "\r\n\r\n")
	if headerEnd != -1 {
		bodyStart = headerEnd + 4
	} else {
		bodyStart = len(dataStr)
	}

	return statusCode, statusLine, headers, bodyStart, nil
}

// Scan performs the HTTP proxy detection scan.
func (scanner *Scanner) Scan(ctx context.Context, dialGroup *zgrab2.DialerGroup, target *zgrab2.ScanTarget) (zgrab2.ScanStatus, any, error) {
	var results ScanResults

	// Connect to target
	conn, err := dialGroup.Dial(ctx, target)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, fmt.Errorf("failed to connect: %w", err)
	}
	defer zgrab2.CloseConnAndHandleError(conn)

	// Send proxy GET request
	request := scanner.buildProxyRequest()
	_, err = conn.Write(request)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), &results, fmt.Errorf("failed to send request: %w", err)
	}

	// Read complete response (handles chunked encoding)
	responseData, err := readFullResponse(ctx, conn, scanner.config.MaxResponseSize)
	if err != nil && len(responseData) == 0 {
		return zgrab2.TryGetScanStatus(err), &results, fmt.Errorf("failed to read response: %w", err)
	}

	if scanner.config.IncludeRawResponse {
		results.RawResponse = string(responseData)
	}

	// Parse HTTP response
	statusCode, statusLine, headers, bodyStart, parseErr := parseHTTPResponse(responseData)
	if parseErr != nil {
		results.Error = parseErr.Error()
		if scanner.config.IncludeRawResponse && results.RawResponse == "" {
			results.RawResponse = string(responseData)
		}
		return zgrab2.SCAN_PROTOCOL_ERROR, &results, parseErr
	}

	results.StatusCode = statusCode
	results.StatusLine = statusLine
	results.Headers = headers

	// Extract body if requested
	if bodyStart < len(responseData) {
		body := string(responseData[bodyStart:])
		results.BodyLength = len(body)
		if scanner.config.IncludeBody {
			if len(body) > scanner.config.MaxBodySize {
				results.Body = body[:scanner.config.MaxBodySize]
			} else {
				results.Body = body
			}
		}
	}

	results.ProxySupported = statusCode >= 200 && statusCode < 400 || statusCode == 407

	return zgrab2.SCAN_SUCCESS, &results, nil
}

// readFullResponse reads the complete HTTP response, handling chunked encoding.
func readFullResponse(ctx context.Context, conn net.Conn, maxSize int) ([]byte, error) {
	// Set a read timeout
	readTimeout := 5 * time.Second
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining < readTimeout {
			readTimeout = remaining
		}
	}

	var response []byte
	buf := make([]byte, 4096)
	totalRead := 0

	for totalRead < maxSize {
		// Set deadline for each read
		conn.SetReadDeadline(time.Now().Add(readTimeout))

		n, err := conn.Read(buf)
		if n > 0 {
			response = append(response, buf[:n]...)
			totalRead += n

			// Check if we've received a complete HTTP response
			if isResponseComplete(response) {
				break
			}
		}

		if err != nil {
			if err.Error() == "EOF" && len(response) > 0 {
				// Got EOF but we have data, that's fine
				break
			}
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() && len(response) > 0 {
				// Timeout but we have data, that's fine
				break
			}
			if len(response) == 0 {
				return nil, err
			}
			break
		}
	}

	return response, nil
}

// isResponseComplete checks if we have received a complete HTTP response.
func isResponseComplete(response []byte) bool {
	respStr := string(response)

	// First, check if we have the end of headers
	headerEnd := strings.Index(respStr, "\r\n\r\n")
	if headerEnd == -1 {
		return false // Haven't received all headers yet
	}

	headers := strings.ToLower(respStr[:headerEnd])

	// Check for chunked transfer encoding
	if strings.Contains(headers, "transfer-encoding: chunked") {
		// For chunked, look for the final chunk marker "0\r\n\r\n" or "0\r\n" followed by trailer headers
		body := respStr[headerEnd+4:]
		// The final chunk is "0\r\n" followed by optional trailers and "\r\n"
		return strings.Contains(body, "\r\n0\r\n")
	}

	// Check for content-length
	for _, line := range strings.Split(respStr[:headerEnd], "\r\n") {
		lineLower := strings.ToLower(line)
		if strings.HasPrefix(lineLower, "content-length:") {
			clStr := strings.TrimSpace(strings.TrimPrefix(lineLower, "content-length:"))
			if cl, err := strconv.Atoi(clStr); err == nil {
				bodyLen := len(response) - headerEnd - 4
				return bodyLen >= cl
			}
		}
	}

	// No content-length or chunked encoding - for HTTP/1.1 with keep-alive,
	// we need to rely on having received some reasonable amount of data
	// For connection: close, server will close the connection
	if strings.Contains(headers, "connection: close") {
		// Server will close connection when done, keep reading
		return false
	}

	// If we have headers and some body data, consider it complete enough
	bodyLen := len(response) - headerEnd - 4
	return bodyLen > 0
}
