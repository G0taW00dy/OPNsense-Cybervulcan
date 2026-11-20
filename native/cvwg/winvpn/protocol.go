package winvpn

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Pipe protocol between the tray app (client) and the elevated helper
// (server): one JSON object per line, one response per request.
//
//	{"op":"start","start":{...StartRequest...}}
//	{"op":"stop"}
//	{"op":"status"}
//
// Anything else - unknown ops, unknown fields, extra data, oversized lines,
// invalid parameters - is refused. There is deliberately no way to pass a
// command, a path or a file name.
const (
	OpStart  = "start"
	OpStop   = "stop"
	OpStatus = "status"

	// MaxMessageBytes bounds one request or response line.
	MaxMessageBytes = 16 * 1024

	// ProtocolVersion is reported in every response.
	ProtocolVersion = 1

	pipePrefix = `\\.\pipe\Cybervulcan-vpn-`

	// HelperFlag is the command-line switch that turns the app exe into
	// the elevated helper: <exe> --vpn-helper <nonce> <user SID>.
	HelperFlag = "--vpn-helper"
)

// Request is one message from the tray app.
type Request struct {
	Op    string        `json:"op"`
	Start *StartRequest `json:"start,omitempty"`
}

// Session states reported by Status.
const (
	StateOff      = "off"
	StateStarting = "starting"
	StateOn       = "on"
	StateError    = "error"
)

// Status describes the adapter session.
type Status struct {
	State string `json:"state"`
	Mode  string `json:"mode,omitempty"`

	// From the WireGuard transport.
	LastHandshake int64 `json:"lastHandshake,omitempty"` // unix seconds
	RxBytes       int64 `json:"rx,omitempty"`
	TxBytes       int64 `json:"tx,omitempty"`

	// Error is plain English, set when State is "error".
	Error string `json:"error,omitempty"`
}

// Response is the helper's answer.
type Response struct {
	V      int     `json:"v"`
	OK     bool    `json:"ok"`
	Error  string  `json:"error,omitempty"`
	Status *Status `json:"status,omitempty"`
}

// DecodeRequest parses and validates one request line.
func DecodeRequest(line []byte) (Request, error) {
	var r Request
	if len(line) > MaxMessageBytes {
		return r, errors.New("request too large")
	}
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return Request{}, errors.New("malformed request")
	}
	if dec.More() {
		return Request{}, errors.New("malformed request: trailing data")
	}
	switch r.Op {
	case OpStart:
		if r.Start == nil {
			return Request{}, errors.New("start request without parameters")
		}
		if err := r.Start.Validate(); err != nil {
			return Request{}, err
		}
	case OpStop, OpStatus:
		if r.Start != nil {
			return Request{}, fmt.Errorf("%s takes no parameters", r.Op)
		}
	default:
		return Request{}, errors.New("unknown request")
	}
	return r, nil
}

// EncodeLine marshals v as one protocol line (with the trailing newline).
func EncodeLine(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	if len(b)+1 > MaxMessageBytes {
		return nil, errors.New("message too large")
	}
	return append(b, '\n'), nil
}

// DecodeResponse parses one response line from the helper.
func DecodeResponse(line []byte) (Response, error) {
	var r Response
	if len(line) > MaxMessageBytes {
		return r, errors.New("response too large")
	}
	if err := json.Unmarshal(line, &r); err != nil {
		return Response{}, errors.New("malformed response from the helper")
	}
	if r.V != ProtocolVersion {
		return Response{}, errors.New("the helper is a different version - restart the app")
	}
	return r, nil
}

// NewNonce makes the random part of a pipe name from 16 random bytes.
func NewNonce(random []byte) (string, error) {
	if len(random) != 16 {
		return "", errors.New("nonce needs 16 bytes")
	}
	return hex.EncodeToString(random), nil
}

var (
	nonceRe = regexp.MustCompile(`^[0-9a-f]{32}$`)
	// A user account SID: S-1-5-21-a-b-c-rid (domain or local accounts) or
	// S-1-12-1-... (Microsoft Entra ID accounts).
	userSIDRe = regexp.MustCompile(`^S-1-(5-21|12-1)(-[0-9]{1,10}){1,8}$`)
)

// ValidNonce reports whether s is a nonce made by NewNonce.
func ValidNonce(s string) bool { return nonceRe.MatchString(s) }

// ValidUserSID reports whether s looks like a user account SID (not a
// group, service or well-known SID).
func ValidUserSID(s string) bool { return userSIDRe.MatchString(s) }

// PipeName is the helper's control pipe for nonce.
func PipeName(nonce string) (string, error) {
	if !ValidNonce(nonce) {
		return "", errors.New("invalid pipe nonce")
	}
	return pipePrefix + nonce, nil
}

// PacketPipeName is the helper's packet pipe for nonce (frame.go).
func PacketPipeName(nonce string) (string, error) {
	n, err := PipeName(nonce)
	if err != nil {
		return "", err
	}
	return n + "-pkt", nil
}

// PipeSDDL is the pipe's security descriptor: owned by Administrators (the
// tray app checks this, so a pipe squatted by a normal process is refused);
// only the given user may read/write (no FILE_CREATE_PIPE_INSTANCE, so the
// user's other processes cannot add a rogue server instance); medium
// integrity so the non-elevated tray app can connect.
func PipeSDDL(userSID string) (string, error) {
	if !ValidUserSID(userSID) {
		return "", errors.New("invalid user SID")
	}
	// 0x120083 = READ_CONTROL | SYNCHRONIZE | FILE_READ_DATA |
	// FILE_WRITE_DATA | FILE_READ_ATTRIBUTES.
	return "O:BAG:BAD:P(A;;0x120083;;;" + userSID + ")(A;;GA;;;SY)S:(ML;;NW;;;ME)", nil
}

// HelperArgs builds the helper's command line arguments (after the exe).
func HelperArgs(nonce, userSID string) (string, error) {
	if !ValidNonce(nonce) || !ValidUserSID(userSID) {
		return "", errors.New("invalid helper arguments")
	}
	return HelperFlag + " " + nonce + " " + userSID, nil
}

// ParseHelperArgs validates the helper's arguments (everything after the
// exe name): exactly the flag, a nonce and a user SID.
func ParseHelperArgs(args []string) (nonce, userSID string, err error) {
	if len(args) != 3 || args[0] != HelperFlag || !ValidNonce(args[1]) || !ValidUserSID(args[2]) {
		return "", "", errors.New("usage: " + HelperFlag + " <nonce> <user SID>")
	}
	return args[1], args[2], nil
}

// FriendlyError turns low-level errors into text for the user.
func FriendlyError(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	low := strings.ToLower(s)
	switch {
	case strings.Contains(low, "cancelled by the user") || strings.Contains(low, "operation was canceled by the user"):
		return "The admin prompt was cancelled, so the home link was not turned on."
	case strings.Contains(low, "wintun.dll"):
		return "wintun.dll is missing next to the app - reinstall Cybervulcan."
	case strings.Contains(low, "access is denied"):
		return "Windows refused the change (admin rights are needed for the home link)."
	}
	return s
}

// ParseStartJSON decodes the tray app's start request strictly (unknown
// fields refused) and validates it.
func ParseStartJSON(b []byte) (StartRequest, error) {
	var r StartRequest
	if len(b) > MaxMessageBytes {
		return r, errors.New("request too large")
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return StartRequest{}, errors.New("bad home link settings")
	}
	if dec.More() {
		return StartRequest{}, errors.New("bad home link settings")
	}
	return r, r.Validate()
}
