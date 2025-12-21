// Package socks4 contains the zgrab2 Module implementation for SOCKS4.
package socks4

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"

	log "github.com/sirupsen/logrus"

	"github.com/zmap/zgrab2"
)

// ScanResults is the output of the scan.
type ScanResults struct {
	Version                       string            `json:"version,omitempty"`
	ConnectionResponse            string            `json:"connection_response,omitempty"`
	ConnectionResponseExplanation map[string]string `json:"connection_response_explanation,omitempty"`
	IsSOCKS4a                     bool              `json:"is_socks4a,omitempty"`
}

// Flags are the SOCKS4-specific command-line flags.
type Flags struct {
	zgrab2.BaseFlags
	UseSocks4a bool   `long:"socks4a" description:"Use SOCKS4a protocol (domain name resolution on server)"`
	DestIP     string `long:"dest-ip" default:"1.1.1.1" description:"Destination IP for connect request (SOCKS4 mode)"`
	DestPort   uint16 `long:"dest-port" default:"80" description:"Destination port for connect request"`
	DestDomain string `long:"dest-domain" default:"example.com" description:"Destination domain for connect request (SOCKS4a mode)"`
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

// Connection holds the state for a single connection to the SOCKS4 server.
type Connection struct {
	config  *Flags
	results ScanResults
	conn    net.Conn
}

// RegisterModule registers the socks4 zgrab2 module.
func RegisterModule() {
	var module Module
	_, err := zgrab2.AddCommand("socks4", "Socket Secure Proxy (SOCKS4)", module.Description(), 1080, &module)
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
	return "Perform a SOCKS4 scan"
}

// Validate flags
func (f *Flags) Validate(_ []string) (err error) {
	return
}

// Help returns this module's help string.
func (f *Flags) Help() string {
	return ""
}

// Protocol returns the protocol identifier for the scanner.
func (scanner *Scanner) Protocol() string {
	return "socks4"
}

// GetDialerGroupConfig returns the dialer group configuration.
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

// readResponse reads a response from the SOCKS4 server.
func (conn *Connection) readResponse() ([]byte, error) {
	resp := make([]byte, 8) // SOCKS4 response is always 8 bytes
	_, err := conn.conn.Read(resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// sendCommand sends a command to the SOCKS4 server.
func (conn *Connection) sendCommand(cmd []byte) error {
	_, err := conn.conn.Write(cmd)
	return err
}

// getReplyDescription returns a human-readable description of the reply code.
func getReplyDescription(code byte) string {
	switch code {
	case 0x5A: // 90
		return "request granted"
	case 0x5B: // 91
		return "request rejected or failed"
	case 0x5C: // 92
		return "request rejected because SOCKS server cannot connect to identd on the client"
	case 0x5D: // 93
		return "request rejected because the client program and identd report different user-ids"
	default:
		return "unknown reply code"
	}
}

// explainResponse converts the raw response into a human-readable explanation.
func explainResponse(resp []byte) map[string]string {
	if len(resp) < 8 {
		return map[string]string{"error": "response too short"}
	}

	port := binary.BigEndian.Uint16(resp[2:4])

	return map[string]string{
		"Version":       fmt.Sprintf("0x%02x", resp[0]),
		"Reply":         fmt.Sprintf("0x%02x (%s)", resp[1], getReplyDescription(resp[1])),
		"Bound Port":    strconv.Itoa(int(port)),
		"Bound Address": fmt.Sprintf("%d.%d.%d.%d", resp[4], resp[5], resp[6], resp[7]),
	}
}

// buildConnectRequest builds a SOCKS4 CONNECT request.
func (conn *Connection) buildConnectRequest() []byte {
	// Format: VN(1) + CD(1) + DSTPORT(2) + DSTIP(4) + USERID(variable) + NULL(1)

	// Parse destination IP
	ip := net.ParseIP(conn.config.DestIP).To4()
	if ip == nil {
		// Fallback to Cloudflare if parsing fails
		ip = net.ParseIP("1.1.1.1").To4()
	}

	req := make([]byte, 9)
	req[0] = 0x04 // VN: SOCKS version 4
	req[1] = 0x01 // CD: CONNECT command
	binary.BigEndian.PutUint16(req[2:4], conn.config.DestPort)
	copy(req[4:8], ip)
	req[8] = 0x00 // NULL terminator for USERID (empty user ID)

	return req
}

// buildConnectRequestSocks4a builds a SOCKS4a CONNECT request with domain name.
func (conn *Connection) buildConnectRequestSocks4a() []byte {
	// SOCKS4a uses invalid IP (0.0.0.x where x != 0) to signal domain name follows
	// Format: VN(1) + CD(1) + DSTPORT(2) + DSTIP(4) + USERID(variable) + NULL(1) + DOMAIN + NULL(1)

	req := make([]byte, 9)
	req[0] = 0x04 // VN: SOCKS version 4
	req[1] = 0x01 // CD: CONNECT command
	binary.BigEndian.PutUint16(req[2:4], conn.config.DestPort)
	req[4], req[5], req[6], req[7] = 0x00, 0x00, 0x00, 0x01 // DSTIP: 0.0.0.1 (signals SOCKS4a)
	req[8] = 0x00                                           // NULL terminator for USERID (empty user ID)

	// Append domain name and NULL terminator
	req = append(req, []byte(conn.config.DestDomain)...)
	req = append(req, 0x00)

	return req
}

// PerformConnectionRequest sends a connection request to the SOCKS4 server.
func (conn *Connection) PerformConnectionRequest() error {
	var req []byte

	if conn.config.UseSocks4a {
		req = conn.buildConnectRequestSocks4a()
		conn.results.IsSOCKS4a = true
	} else {
		req = conn.buildConnectRequest()
		conn.results.IsSOCKS4a = false
	}

	conn.results.Version = "0x04"

	err := conn.sendCommand(req)
	if err != nil {
		return fmt.Errorf("error sending connection request: %w", err)
	}

	// Read connection response
	resp, err := conn.readResponse()
	if err != nil {
		return fmt.Errorf("error reading connection response: %w", err)
	}

	conn.results.ConnectionResponse = hex.EncodeToString(resp)
	conn.results.ConnectionResponseExplanation = explainResponse(resp)

	// Check reply code (0x5A = success)
	if resp[1] != 0x5A {
		return fmt.Errorf("connection request failed with reply code: 0x%02x (%s)", resp[1], getReplyDescription(resp[1]))
	}

	return nil
}

// Scan performs the configured scan on the SOCKS4 server.
func (scanner *Scanner) Scan(ctx context.Context, dialGroup *zgrab2.DialerGroup, target *zgrab2.ScanTarget) (zgrab2.ScanStatus, any, error) {
	conn, err := dialGroup.Dial(ctx, target)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, fmt.Errorf("error opening connection to %s: %w", target.String(), err)
	}
	defer zgrab2.CloseConnAndHandleError(conn)

	results := ScanResults{}
	socks4Conn := Connection{conn: conn, config: scanner.config, results: results}

	err = socks4Conn.PerformConnectionRequest()
	if err != nil {
		return zgrab2.TryGetScanStatus(err), &socks4Conn.results, fmt.Errorf("error during connection request: %w", err)
	}

	return zgrab2.SCAN_SUCCESS, &socks4Conn.results, nil
}
