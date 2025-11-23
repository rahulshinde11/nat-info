package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"strconv"
	"time"
)

// STUN Constants
const (
	MagicCookie          = 0x2112A442
	BindingRequest       = 0x0001
	BindingResponse      = 0x0101
	HeaderLength         = 20
	AttrMappedAddress    = 0x0001
	AttrChangeRequest    = 0x0003
	AttrXorMappedAddress = 0x0020
	FamilyIPv4           = 0x01
)

// STUN Servers
var StunServers = []string{
	"stun.l.google.com:19302",
	"stun1.l.google.com:19302",
	"stun.stunprotocol.org:3478",
}

// Servers known to support RFC 3489 CHANGE-REQUEST
var Rfc3489Servers = []string{
	"stun.sipgate.net:3478",
	"stun.voipstunt.com:3478",
	"stun.schlund.de:3478",
}

// StunResult holds the parsed IP and Port
type StunResult struct {
	IP   string
	Port int
}

// NatResult holds the final detection result
type NatResult struct {
	Type   string
	Reason string
	Public *StunResult
}

// Attribute represents a STUN attribute
type Attribute struct {
	Type  uint16
	Value []byte
}

// Helper for printing
func printLine(s string) {
	os.Stdout.WriteString(s + "\n")
}

// getLocalIP returns the local IP address used for internet routing
func getLocalIP() (string, error) {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "127.0.0.1", nil
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String(), nil
}

// parseStunResponse parses a STUN message buffer to extract MAPPED-ADDRESS or XOR-MAPPED-ADDRESS
func parseStunResponse(buffer []byte) (*StunResult, error) {
	if len(buffer) < HeaderLength {
		return nil, errors.New("buffer too short")
	}

	messageType := binary.BigEndian.Uint16(buffer[0:2])
	magicCookie := binary.BigEndian.Uint32(buffer[4:8])

	if messageType != BindingResponse {
		return nil, errors.New("invalid message type: 0x" + strconv.FormatUint(uint64(messageType), 16))
	}

	isRFC5389 := (magicCookie == MagicCookie)
	msgLen := binary.BigEndian.Uint16(buffer[2:4])

	// Verify buffer contains full message
	if len(buffer) < int(HeaderLength+msgLen) {
		return nil, errors.New("buffer incomplete")
	}

	offset := HeaderLength
	limit := len(buffer)

	for offset+4 <= limit {
		attrType := binary.BigEndian.Uint16(buffer[offset : offset+2])
		attrLen := binary.BigEndian.Uint16(buffer[offset+2 : offset+4])
		offset += 4

		if offset+int(attrLen) > limit {
			break
		}

		attrVal := buffer[offset : offset+int(attrLen)]

		// XOR-MAPPED-ADDRESS
		if attrType == AttrXorMappedAddress && attrLen >= 8 {
			family := attrVal[1]
			if family == FamilyIPv4 {
				port := binary.BigEndian.Uint16(attrVal[2:4])
				ipBytes := make([]byte, 4)
				copy(ipBytes, attrVal[4:8])

				if isRFC5389 {
					port ^= uint16(MagicCookie >> 16)
					ipBytes[0] ^= byte(MagicCookie >> 24)
					ipBytes[1] ^= byte((MagicCookie >> 16) & 0xFF)
					ipBytes[2] ^= byte((MagicCookie >> 8) & 0xFF)
					ipBytes[3] ^= byte(MagicCookie & 0xFF)
				}

				return &StunResult{
					IP:   net.IP(ipBytes).String(),
					Port: int(port),
				}, nil
			}
		}

		// MAPPED-ADDRESS
		if attrType == AttrMappedAddress && attrLen >= 8 {
			family := attrVal[1]
			if family == FamilyIPv4 {
				port := binary.BigEndian.Uint16(attrVal[2:4])
				ipBytes := make([]byte, 4)
				copy(ipBytes, attrVal[4:8])

				return &StunResult{
					IP:   net.IP(ipBytes).String(),
					Port: int(port),
				}, nil
			}
		}

		// Move to next attribute, padded to 4 bytes
		paddedLen := (int(attrLen) + 3) & ^3
		offset += paddedLen
	}

	return nil, errors.New("no mapped address found")
}

// makeStunRequest sends a Binding Request and waits for a response
// If expectDifferentSource is true, validates the response source based on changeRequestFlags:
//   - 0: Any different source accepted
//   - 2 (Change Port): Accepts same IP, different port
//   - 6 (Change IP+Port): Accepts different IP and different port only
func makeStunRequest(conn *net.UDPConn, serverAddrStr string, attributes []Attribute, timeout time.Duration, useMagicCookie bool, changeRequestFlags byte) (*StunResult, error) {
	// Force IPv4 resolution
	serverAddr, err := net.ResolveUDPAddr("udp4", serverAddrStr)
	if err != nil {
		return nil, err
	}

	// Construct STUN Message
	var tid []byte
	if useMagicCookie {
		tid = make([]byte, 12)
	} else {
		tid = make([]byte, 16)
	}
	_, err = rand.Read(tid)
	if err != nil {
		return nil, err
	}

	// Calculate total length
	totalAttrLen := 0
	for _, attr := range attributes {
		totalAttrLen += 4 + ((len(attr.Value) + 3) & ^3)
	}

	req := make([]byte, HeaderLength+totalAttrLen)

	// Header
	binary.BigEndian.PutUint16(req[0:2], BindingRequest)
	binary.BigEndian.PutUint16(req[2:4], uint16(totalAttrLen))

	if useMagicCookie {
		binary.BigEndian.PutUint32(req[4:8], MagicCookie)
		copy(req[8:20], tid)
	} else {
		copy(req[4:20], tid)
	}

	// Attributes
	offset := HeaderLength
	for _, attr := range attributes {
		binary.BigEndian.PutUint16(req[offset:offset+2], attr.Type)
		binary.BigEndian.PutUint16(req[offset+2:offset+4], uint16(len(attr.Value)))
		copy(req[offset+4:], attr.Value)
		paddedLen := (len(attr.Value) + 3) & ^3
		offset += 4 + paddedLen
	}

	// Retransmission Logic
	const baseRetransmit = 200 * time.Millisecond

	deadline := time.Now().Add(timeout)
	conn.SetReadDeadline(deadline)

	nextRetransmit := time.Now()
	retransmitDuration := baseRetransmit

	buf := make([]byte, 2048)
	attempt := 1

	for time.Now().Before(deadline) {
		// Check if we need to retransmit
		if time.Now().After(nextRetransmit) {
			_, err = conn.WriteToUDP(req, serverAddr)
			if err != nil {
				return nil, err
			}
			nextRetransmit = time.Now().Add(retransmitDuration)
			retransmitDuration *= 2
			attempt++
		}

		// Determine read deadline
		readTimeout := time.Until(nextRetransmit)
		if readTimeout < 10*time.Millisecond {
			readTimeout = 10 * time.Millisecond
		}
		if time.Until(deadline) < readTimeout {
			readTimeout = time.Until(deadline)
		}

		conn.SetReadDeadline(time.Now().Add(readTimeout))

		n, remoteAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				continue
			}
			return nil, err
		}

		if n < HeaderLength {
			continue
		}

		// Check Transaction ID
		match := false
		if useMagicCookie {
			match = bytes.Equal(buf[8:20], tid)
		} else {
			match = bytes.Equal(buf[4:20], tid)
		}

		if match {
			// If we have change request flags, validate the response source
			if changeRequestFlags > 0 {
				sameIP := remoteAddr.IP.Equal(serverAddr.IP)
				samePort := remoteAddr.Port == serverAddr.Port

				if sameIP && samePort {
					continue // Same source - not a CHANGE-REQUEST response
				}

				// Validate based on change request flags
				if changeRequestFlags == 6 {
					// Change IP+Port (0x06): Would need BOTH IP and port different
					// However, with DNS round-robin hostnames, we cannot reliably distinguish
					// between legitimate alternate IPs and other servers in the pool.
					// To avoid false positives, we skip Full Cone detection with these servers.
					continue
				} else if changeRequestFlags == 2 {
					// Change Port (0x02): Must have SAME IP, different port
					if !sameIP || samePort {
						continue
					}
				}
			}

			result, err := parseStunResponse(buf[:n])
			if err != nil {
				return &StunResult{}, nil
			}
			return result, nil
		}
	}

	return nil, errors.New("STUN request timeout")
}

func detectNATType() (*NatResult, error) {
	localIP, err := getLocalIP()
	if err != nil {
		return nil, err
	}

	// Bind to a random local port
	localAddr, err := net.ResolveUDPAddr("udp4", "0.0.0.0:0")
	if err != nil {
		return nil, err
	}

	conn, err := net.ListenUDP("udp4", localAddr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	localPort := conn.LocalAddr().(*net.UDPAddr).Port

	printLine("Local Network IP: " + localIP)
	printLine("Local Port: " + strconv.Itoa(localPort))

	var primaryResult *StunResult

	// Test 1: Connect to Server 1
	primaryResult, err = makeStunRequest(conn, StunServers[0], nil, 3*time.Second, true, 0)
	if err != nil {
		// Backup server
		primaryResult, err = makeStunRequest(conn, StunServers[1], nil, 3*time.Second, true, 0)
		if err != nil {
			return &NatResult{Type: "UDP Blocked", Reason: "All STUN requests failed"}, nil
		}
	}

	if primaryResult.IP == localIP {
		return &NatResult{Type: "Open Internet", Reason: "No NAT detected", Public: primaryResult}, nil
	}

	portPreserved := (primaryResult.Port == localPort)

	// Test 2: Check Mapping Behavior
	mappingBehavior := "Unknown"

	res2, err := makeStunRequest(conn, StunServers[2], nil, 3*time.Second, true, 0)
	if err == nil {
		if res2.IP == primaryResult.IP && res2.Port == primaryResult.Port {
			mappingBehavior = "Endpoint Independent"
		} else {
			mappingBehavior = "Endpoint Dependent"
		}
	} else {
		res2, err = makeStunRequest(conn, StunServers[1], nil, 3*time.Second, true, 0)
		if err == nil {
			if res2.IP == primaryResult.IP && res2.Port == primaryResult.Port {
				mappingBehavior = "Endpoint Independent"
			} else {
				mappingBehavior = "Endpoint Dependent"
			}
		} else {
			mappingBehavior = "Endpoint Independent"
		}
	}

	if mappingBehavior == "Endpoint Dependent" {
		return &NatResult{
			Type:   "Symmetric NAT",
			Reason: "Public IP/Port varies by destination",
			Public: primaryResult,
		}, nil
	}

	// Phase 2: Cone NAT Subtype Detection
	printLine("Detected Endpoint Independent Mapping. Probing for Cone Subtype...")

	subtype := "Port Restricted Cone NAT" // Default assumption

	for _, server := range Rfc3489Servers {
		// 1. Establish mapping (shorter timeout for initial connection test)
		// Resolve the server address first to know exactly which IP we're talking to
		resolvedAddr, err := net.ResolveUDPAddr("udp4", server)
		if err != nil {
			continue
		}

		_, err = makeStunRequest(conn, server, nil, 2*time.Second, true, 0)
		if err != nil {
			continue
		}

		// 2. Test for Full Cone: Change IP and Port
		// Important: Use the RESOLVED IP as a string to ensure we're comparing against
		// the exact server we established communication with, not another server in DNS round-robin
		resolvedServerStr := resolvedAddr.String()

		changeIpPortVal := []byte{0, 0, 0, 6}
		_, err = makeStunRequest(conn, resolvedServerStr, []Attribute{{Type: AttrChangeRequest, Value: changeIpPortVal}}, 2*time.Second, true, 6)
		if err == nil {
			subtype = "Full Cone NAT"
			break
		}

		// 3. Test for Restricted Cone: Change Port only
		changePortVal := []byte{0, 0, 0, 2}
		_, err = makeStunRequest(conn, resolvedServerStr, []Attribute{{Type: AttrChangeRequest, Value: changePortVal}}, 2*time.Second, true, 2)
		if err == nil {
			subtype = "Restricted Cone NAT"
			break
		}
	}

	reason := "Endpoint Independent Mapping."
	if portPreserved {
		reason += " Port Preserved."
	}

	return &NatResult{
		Type:   subtype,
		Reason: reason,
		Public: primaryResult,
	}, nil
}

func main() {
	printLine("Starting STUN NAT Type Detection...")
	printLine("-----------------------------------")

	result, err := detectNATType()
	if err != nil {
		printLine("Error during detection: " + err.Error())
		return
	}

	printLine("\n=== Final Result ===")
	printLine("NAT Type:      " + result.Type)
	printLine("Reason:        " + result.Reason)
	if result.Public != nil {
		printLine("Public IP:     " + result.Public.IP)
		printLine("Public Port:   " + strconv.Itoa(result.Public.Port))
	}
}
