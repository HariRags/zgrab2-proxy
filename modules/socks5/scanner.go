// Package socks5 contains the zgrab2 Module implementation for SOCKS5.
package socks5

import (
	"bufio"
	"context"
	"encoding/hex"
	"errors"
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

// ScanResults is the output of the scan.
type ScanResults struct {
	Version                       string            `json:"version,omitempty"`
	MethodSelection               string            `json:"method_selection,omitempty"`
	ConnectionResponse            string            `json:"connection_response,omitempty"`
	ConnectionResponseExplanation map[string]string `json:"connection_response_explanation,omitempty"`

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

// Flags are the SOCKS5-specific command-line flags.
type Flags struct {
	zgrab2.BaseFlags
	DestDomain string `long:"dest-domain" default:"example.com" description:"Destination domain for connect request (used for SOCKS4a or as SNI for HTTPS)"`
	DestAddr string `long:"dest-addr" default:"104.18.27.120" description:"Destination address for connect request (IPv4 or IPv6)"`
	DestPort uint16 `long:"dest-port" default:"80" description:"Destination port for connect request"`

	// Page fetching options
	FetchPage   bool   `long:"fetch-page" description:"Fetch a page through the SOCKS tunnel after successful connection"`
	PagePath    string `long:"page-path" default:"/" description:"Path to fetch from target server"`
	MaxPageSize int    `long:"max-page-size" default:"65536" description:"Maximum page content size to read in bytes"`
	UseHTTPS    bool   `long:"use-https" description:"Use HTTPS for page fetch (default: true if dest port is 443)"`
	UserAgent   string `long:"user-agent" default:"curl/7.81.0" description:"User-Agent header value"`
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

// Connection holds the state for a single connection to the SOCKS5 server.
type Connection struct {
	config  *Flags
	results ScanResults
	conn    net.Conn
}

// RegisterModule registers the socks5 zgrab2 module.
func RegisterModule() {
	var module Module
	_, err := zgrab2.AddCommand("socks5", "Socket Secure Proxy (SOCKS5)", module.Description(), 1080, &module)
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
	return "Perform a SOCKS5 scan"
}

// Validate flags
func (f *Flags) Validate(_ []string) (err error) {
	if f.MaxPageSize <= 0 {
		f.MaxPageSize = 65536
	}
	// Auto-enable HTTPS if port 443
	if f.DestPort == 443 && !f.UseHTTPS {
		f.UseHTTPS = true
	}
	return nil
}

// Help returns this module's help string.
func (f *Flags) Help() string {
	return ""
}

// Protocol returns the protocol identifier for the scanner.
func (scanner *Scanner) Protocol() string {
	return "socks5"
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

// readResponse reads a response from the SOCKS5 server.
func (conn *Connection) readResponse(expectedLength int) ([]byte, error) {
	resp := make([]byte, expectedLength)
	_, err := conn.conn.Read(resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// sendCommand sends a command to the SOCKS5 server.
func (conn *Connection) sendCommand(cmd []byte) error {
	_, err := conn.conn.Write(cmd)
	return err
}

// explainResponse converts the raw response into a human-readable explanation.
func explainResponse(resp []byte) map[string]string {
	if len(resp) < 10 {
		return map[string]string{"error": "response too short"}
	}

	return map[string]string{
		"Version":       fmt.Sprintf("0x%02x (SOCKS Version 5)", resp[0]),
		"Reply":         fmt.Sprintf("0x%02x (%s)", resp[1], getReplyDescription(resp[1])),
		"Reserved":      fmt.Sprintf("0x%02x", resp[2]),
		"Address Type":  fmt.Sprintf("0x%02x (%s)", resp[3], getAddressTypeDescription(resp[3])),
		"Bound Address": fmt.Sprintf("%d.%d.%d.%d", resp[4], resp[5], resp[6], resp[7]),
		"Bound Port":    strconv.Itoa(int(resp[8])<<8 | int(resp[9])),
	}
}

func getReplyDescription(code byte) string {
	switch code {
	case 0x00:
		return "succeeded"
	case 0x01:
		return "general SOCKS server failure"
	case 0x02:
		return "connection not allowed by ruleset"
	case 0x03:
		return "network unreachable"
	case 0x04:
		return "host unreachable"
	case 0x05:
		return "connection refused"
	case 0x06:
		return "TTL expired"
	case 0x07:
		return "command not supported"
	case 0x08:
		return "address type not supported"
	default:
		return "unassigned"
	}
}

func getAddressTypeDescription(code byte) string {
	switch code {
	case 0x01:
		return "IPv4 address"
	case 0x03:
		return "Domain name"
	case 0x04:
		return "IPv6 address"
	default:
		return "unknown"
	}
}

// PerformHandshake performs the SOCKS5 handshake.
func (conn *Connection) PerformHandshake() (bool, error) {
	// Send version identifier/method selection message
	// VER = 0x05, NMETHODS = 2, METHODS = 0x00 (NO AUTH), 0x01 (GSSAPI)
	methods := []byte{0x05, 0x02, 0x00, 0x01}

	err := conn.sendCommand(methods)
	if err != nil {
		return false, fmt.Errorf("error sending version identifier/method selection: %w", err)
	}
	conn.results.Version = "0x05"

	// Read method selection response
	methodSelResp, err := conn.readResponse(2)
	if err != nil {
		return false, fmt.Errorf("error reading method selection response: %w", err)
	}
	conn.results.MethodSelection = hex.EncodeToString(methodSelResp)

	if methodSelResp[1] == 0xFF {
		return true, errors.New("no acceptable authentication methods")
	}

	return false, nil
}

// PerformConnectionRequest sends a connection request to the SOCKS5 server.
func (conn *Connection) PerformConnectionRequest() error {
	// Send a connection request
	// VER = 0x05, CMD = CONNECT, RSV = 0x00
	port := conn.config.DestPort
	addr := net.ParseIP(conn.config.DestAddr)
	if addr == nil {
		return fmt.Errorf("invalid destination address: %s", conn.config.DestAddr)
	}

	var req []byte
	if ipv4 := addr.To4(); ipv4 != nil {
		// ATYP = IPV4
		req = make([]byte, 4+net.IPv4len+2)
		req[0] = 0x05 // VER
		req[1] = 0x01 // CMD
		req[2] = 0x00 // RSV
		req[3] = 0x01 // ATYP
		copy(req[4:], ipv4)
		req[4+net.IPv4len] = byte(port >> 8)
		req[4+net.IPv4len+1] = byte(port)
	} else if ipv6 := addr.To16(); ipv6 != nil {
		// ATYP = IPV6
		req = make([]byte, 4+net.IPv6len+2)
		req[0] = 0x05 // VER
		req[1] = 0x01 // CMD
		req[2] = 0x00 // RSV
		req[3] = 0x04 // ATYP
		copy(req[4:], ipv6)
		req[4+net.IPv6len] = byte(port >> 8)
		req[4+net.IPv6len+1] = byte(port)
	} else {
		return fmt.Errorf("invalid IP address: %s", conn.config.DestAddr)
	}

	err := conn.sendCommand(req)
	if err != nil {
		return fmt.Errorf("error sending connection request: %w", err)
	}

	// Read connection response
	resp, err := conn.readResponse(10)
	if err != nil {
		return fmt.Errorf("error reading connection response: %w", err)
	}
	conn.results.ConnectionResponse = hex.EncodeToString(resp)
	conn.results.ConnectionResponseExplanation = explainResponse(resp)

	if resp[1] > 0x00 {
		return fmt.Errorf("connection request failed with response: %x", resp)
	}

	return nil
}

// buildHTTPRequest builds the HTTP GET request bytes for fetching the page.
func (conn *Connection) buildHTTPRequest() []byte {
	var host string
	host = conn.config.DestDomain

	request := fmt.Sprintf(
		"GET %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"User-Agent: %s\r\n"+
			"Accept: */*\r\n"+
			"\r\n",
		conn.config.PagePath, host, conn.config.UserAgent)
	return []byte(request)
}

// fetchPageContent fetches the page content through the established SOCKS tunnel.
func (conn *Connection) fetchPageContent(ctx context.Context) error {
	// If HTTPS is enabled, wrap the connection with TLS
	var pageConn net.Conn = conn.conn
	if conn.config.UseHTTPS {
		var serverName string
		serverName = conn.config.DestDomain

		tlsConfig := &tls.Config{
			ServerName:         serverName,
			InsecureSkipVerify: true, // For scanning purposes
		}
		pageConn = tls.Client(conn.conn, tlsConfig)
	}

	// Set deadline if context has one
	if deadline, ok := ctx.Deadline(); ok {
		if err := pageConn.SetWriteDeadline(deadline); err != nil {
			return fmt.Errorf("failed to set write deadline: %w", err)
		}
		if err := pageConn.SetReadDeadline(deadline); err != nil {
			return fmt.Errorf("failed to set read deadline: %w", err)
		}
	}

	// Send HTTP GET request
	request := conn.buildHTTPRequest()
	_, err := pageConn.Write(request)
	if err != nil {
		return fmt.Errorf("failed to send HTTP request: %w", err)
	}

	// Read HTTP response
	reader := bufio.NewReader(pageConn)
	tp := textproto.NewReader(reader)

	// Read status line
	statusLine, err := tp.ReadLine()
	if err != nil {
		return fmt.Errorf("failed to read status line: %w", err)
	}
	conn.results.PageStatusLine = statusLine

	// Parse status code
	parts := strings.SplitN(statusLine, " ", 3)
	if len(parts) >= 2 {
		statusCode, err := strconv.Atoi(parts[1])
		if err == nil {
			conn.results.PageStatusCode = statusCode
		}
	}

	// Read headers
	headers, err := tp.ReadMIMEHeader()
	if err != nil {
		return fmt.Errorf("failed to read headers: %w", err)
	}
	conn.results.PageHeaders = headers

	// Read body
	body, err := io.ReadAll(io.LimitReader(reader, int64(conn.config.MaxPageSize)))
	if err != nil {
		return fmt.Errorf("failed to read body: %w", err)
	}
	conn.results.PageBody = string(body)

	// Check if body was truncated
	if len(body) == conn.config.MaxPageSize {
		conn.results.PageBodyTruncated = true
	}

	return nil
}

// Scan performs the configured scan on the SOCKS5 server.
func (scanner *Scanner) Scan(ctx context.Context, dialGroup *zgrab2.DialerGroup, target *zgrab2.ScanTarget) (zgrab2.ScanStatus, any, error) {
	conn, err := dialGroup.Dial(ctx, target)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, fmt.Errorf("error opening connection to %s: %w", target.String(), err)
	}
	defer zgrab2.CloseConnAndHandleError(conn)
	results := ScanResults{}
	socks5Conn := Connection{conn: conn, config: scanner.config, results: results}

	have_auth, err := socks5Conn.PerformHandshake()
	if err != nil {
		if have_auth {
			return zgrab2.SCAN_SUCCESS, &socks5Conn.results, nil
		} else {
			return zgrab2.TryGetScanStatus(err), &socks5Conn.results, fmt.Errorf("error during handshake: %w", err)
		}
	}

	err = socks5Conn.PerformConnectionRequest()
	if err != nil {
		return zgrab2.TryGetScanStatus(err), &socks5Conn.results, fmt.Errorf("error during connection request: %w", err)
	}

	if scanner.config.FetchPage {
		err = socks5Conn.fetchPageContent(ctx)
		if err != nil {
			socks5Conn.results.Error = err.Error()
			return zgrab2.SCAN_SUCCESS, &socks5Conn.results, nil
		}
	}
	conn.Close()
	return zgrab2.SCAN_SUCCESS, &socks5Conn.results, nil
}
