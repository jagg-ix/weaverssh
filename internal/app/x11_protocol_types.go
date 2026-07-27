package app

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
)

// ByteOrder represents the byte order for the connection
type ByteOrder binary.ByteOrder

const (
	BigEndian    byte = 0x42 // 'B'
	LittleEndian byte = 0x6c // 'l'
)

const (
	UNTRUSTED_LEVEL = 0
	TRUSTED_LEVEL   = 1
)

// X11 Protocol Constants
const (
	ProtocolMajorVersion = 11
	ProtocolMinorVersion = 0

	// Opcodes
	OpcodeCreateWindow   = 1
	OpcodeChangeProperty = 18
	OpcodeGetProperty    = 20
	OpcodeQueryExtension = 98
	OpcodeNoOperation    = 127

	// SECURITY extension
	SecurityExtensionName = "SECURITY"
	SecurityMajorOpcode   = 138
	SecurityGenerateAuth  = 1
	SecurityRevokeAuth    = 2

	// Auth protocol names
	AuthProtoMITMagicCookie = "MIT-MAGIC-COOKIE-1"
)

// ConnectionSetup represents the initial client connection setup message
type ConnectionSetup struct {
	ByteOrder        byte
	ProtocolMajorVer uint16
	ProtocolMinorVer uint16
	AuthProtoNameLen uint16
	AuthProtoDataLen uint16
	AuthProtoName    string
	AuthProtoData    []byte
}

// ReadConnectionSetup reads and parses the connection setup from the client
func ReadConnectionSetup(r io.Reader) (*ConnectionSetup, error) {
	var setup ConnectionSetup

	// Read fixed header (12 bytes)
	header := make([]byte, 12)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, fmt.Errorf("reading setup header: %w", err)
	}

	setup.ByteOrder = header[0]
	// header[1] is padding

	var bo binary.ByteOrder
	if setup.ByteOrder == BigEndian {
		bo = binary.BigEndian
	} else if setup.ByteOrder == LittleEndian {
		bo = binary.LittleEndian
	} else {
		return nil, fmt.Errorf("invalid byte order: %#x", setup.ByteOrder)
	}

	setup.ProtocolMajorVer = bo.Uint16(header[2:4])
	setup.ProtocolMinorVer = bo.Uint16(header[4:6])
	setup.AuthProtoNameLen = bo.Uint16(header[6:8])
	setup.AuthProtoDataLen = bo.Uint16(header[8:10])

	// Calculate total auth data length (padded to 4-byte boundary)
	namePadded := (setup.AuthProtoNameLen + 3) & ^uint16(3)
	dataPadded := (setup.AuthProtoDataLen + 3) & ^uint16(3)
	totalLen := namePadded + dataPadded

	if totalLen > 0 {
		authBuf := make([]byte, totalLen)
		if _, err := io.ReadFull(r, authBuf); err != nil {
			return nil, fmt.Errorf("reading auth data: %w", err)
		}

		setup.AuthProtoName = string(authBuf[:setup.AuthProtoNameLen])
		dataStart := namePadded
		dataEnd := dataStart + setup.AuthProtoDataLen
		setup.AuthProtoData = authBuf[dataStart:dataEnd]
	}

	return &setup, nil
}

// ConnectionReply represents the server's response to connection setup
type ConnectionReply struct {
	Success          bool
	ProtocolMajorVer uint16
	ProtocolMinorVer uint16
	ReasonLength     uint16
	Reason           string

	// Success fields
	ReleaseNumber      uint32
	ResourceIDBase     uint32
	ResourceIDMask     uint32
	MotionBufferSize   uint32
	VendorLength       uint16
	MaxRequestLength   uint16
	NumScreens         uint8
	NumFormats         uint8
	ImageByteOrder     uint8
	BitmapBitOrder     uint8
	BitmapScanlineUnit uint8
	BitmapScanlinePad  uint8
	MinKeycode         uint8
	MaxKeycode         uint8
	Vendor             string
	Formats            []Format
	Screens            []Screen
}

// Format represents a pixmap format
type Format struct {
	Depth        uint8
	BitsPerPixel uint8
	ScanlinePad  uint8
}

// Screen represents a screen in the display
type Screen struct {
	RootWindow          uint32
	DefaultColormap     uint32
	WhitePixel          uint32
	BlackPixel          uint32
	CurrentInputMasks   uint32
	WidthInPixels       uint16
	HeightInPixels      uint16
	WidthInMillimeters  uint16
	HeightInMillimeters uint16
	MinInstalledMaps    uint16
	MaxInstalledMaps    uint16
	RootVisual          uint32
	BackingStores       uint8
	SaveUnders          uint8
	RootDepth           uint8
	NumDepths           uint8
	Depths              []Depth
}

// Depth represents a depth/visual combination
type Depth struct {
	Depth      uint8
	NumVisuals uint16
	Visuals    []Visual
}

// Visual represents a visual type
type Visual struct {
	VisualID        uint32
	Class           uint8
	BitsPerRGBValue uint8
	ColormapEntries uint16
	RedMask         uint32
	GreenMask       uint32
	BlueMask        uint32
}

// Write writes the connection reply to the writer
func (cr *ConnectionReply) Write(w io.Writer, bo binary.ByteOrder) error {
	buf := make([]byte, 0, 4096)

	if cr.Success {
		buf = append(buf, 1) // Success
	} else {
		buf = append(buf, 0) // Failed
	}

	buf = append(buf, byte(cr.ReasonLength))

	buf = appendUint16(buf, cr.ProtocolMajorVer, bo)
	buf = appendUint16(buf, cr.ProtocolMinorVer, bo)

	if cr.Success {
		// Calculate additional data length in 4-byte units
		// Placeholder for length - will calculate after building buffer
		lengthPos := len(buf)
		buf = appendUint16(buf, 0, bo)

		buf = appendUint32(buf, cr.ReleaseNumber, bo)
		buf = appendUint32(buf, cr.ResourceIDBase, bo)
		buf = appendUint32(buf, cr.ResourceIDMask, bo)
		buf = appendUint32(buf, cr.MotionBufferSize, bo)
		buf = appendUint16(buf, uint16(len(cr.Vendor)), bo)
		buf = appendUint16(buf, cr.MaxRequestLength, bo)
		buf = append(buf, cr.NumScreens)
		buf = append(buf, cr.NumFormats)
		buf = append(buf, cr.ImageByteOrder)
		buf = append(buf, cr.BitmapBitOrder)
		buf = append(buf, cr.BitmapScanlineUnit)
		buf = append(buf, cr.BitmapScanlinePad)
		buf = append(buf, cr.MinKeycode)
		buf = append(buf, cr.MaxKeycode)
		buf = append(buf, 0, 0, 0, 0) // padding

		// Vendor string
		buf = append(buf, []byte(cr.Vendor)...)
		buf = padTo4(buf)

		// Formats
		for _, f := range cr.Formats {
			buf = append(buf, f.Depth, f.BitsPerPixel, f.ScanlinePad)
			buf = append(buf, 0, 0, 0, 0, 0) // padding
		}

		// Screens
		for _, s := range cr.Screens {
			buf = appendUint32(buf, s.RootWindow, bo)
			buf = appendUint32(buf, s.DefaultColormap, bo)
			buf = appendUint32(buf, s.WhitePixel, bo)
			buf = appendUint32(buf, s.BlackPixel, bo)
			buf = appendUint32(buf, s.CurrentInputMasks, bo)
			buf = appendUint16(buf, s.WidthInPixels, bo)
			buf = appendUint16(buf, s.HeightInPixels, bo)
			buf = appendUint16(buf, s.WidthInMillimeters, bo)
			buf = appendUint16(buf, s.HeightInMillimeters, bo)
			buf = appendUint16(buf, s.MinInstalledMaps, bo)
			buf = appendUint16(buf, s.MaxInstalledMaps, bo)
			buf = appendUint32(buf, s.RootVisual, bo)
			buf = append(buf, s.BackingStores, s.SaveUnders, s.RootDepth, s.NumDepths)

			// Depths would be added here
			// Write depths for this screen
			for _, depth := range s.Depths {
				buf = append(buf, depth.Depth)
				buf = append(buf, 0) // padding
				buf = appendUint16(buf, depth.NumVisuals, bo)
				buf = append(buf, 0, 0, 0, 0) // padding (4 bytes)

				// Write visuals for this depth
				for _, visual := range depth.Visuals {
					buf = appendUint32(buf, visual.VisualID, bo)
					buf = append(buf, visual.Class)
					buf = append(buf, visual.BitsPerRGBValue)
					buf = appendUint16(buf, visual.ColormapEntries, bo)
					buf = appendUint32(buf, visual.RedMask, bo)
					buf = appendUint32(buf, visual.GreenMask, bo)
					buf = appendUint32(buf, visual.BlueMask, bo)
					buf = append(buf, 0, 0, 0, 0) // padding (4 bytes)
				}
			}

		}

		// Now calculate actual length: everything after first 8 bytes, in 4-byte units
		actualLen := (len(buf) - 8) / 4
		bo.PutUint16(buf[lengthPos:lengthPos+2], uint16(actualLen))
	} else {
		// Failure format
		buf = appendUint16(buf, 0, bo) // length
		buf = append(buf, []byte(cr.Reason)...)
		buf = padTo4(buf)
	}

	log.Printf("Connection reply: success=%v, buffer_length=%d bytes", cr.Success, len(buf))
	log.Printf("First 32 bytes: % x", buf[:min(32, len(buf))])
	_, err := w.Write(buf)
	return err
}

// Request represents a generic X11 request
type Request struct {
	Opcode      uint8
	Detail      uint8
	SequenceNum uint16
	Length      uint32
	Data        []byte
}

// ReadRequest reads an X11 request from the reader
func ReadRequest(r io.Reader, bo binary.ByteOrder) (*Request, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}

	req := &Request{
		Opcode: header[0],
		Detail: header[1],
		Length: uint32(bo.Uint16(header[2:4])) * 4,
	}

	if req.Length > 4 {
		req.Data = make([]byte, req.Length-4)
		if _, err := io.ReadFull(r, req.Data); err != nil {
			return nil, err
		}
	}

	return req, nil
}

// Reply represents a generic X11 reply
type Reply struct {
	Type        uint8
	Detail      uint8
	SequenceNum uint16
	Length      uint32
	Data        []byte
}

// Write writes the reply to the writer
func (rep *Reply) Write(w io.Writer, bo binary.ByteOrder) error {

	// Build complete reply: 8-byte header + Data
	totalSize := 32 + (int(rep.Length) * 4)
	buf := make([]byte, totalSize)

	// Bytes 0-7: Header
	buf[0] = rep.Type
	buf[1] = rep.Detail
	bo.PutUint16(buf[2:4], rep.SequenceNum)
	bo.PutUint32(buf[4:8], rep.Length)

	// Bytes 8-31: First 24 bytes of Data
	if len(rep.Data) >= 24 {
		copy(buf[8:32], rep.Data[0:24])
	} else {
		copy(buf[8:8+len(rep.Data)], rep.Data)
	}

	// Bytes 32+: Additional data (if Length > 0)
	if rep.Length > 0 && len(rep.Data) > 24 {
		copy(buf[32:], rep.Data[24:])
	}

	log.Printf("DEBUG: Reply - type=%d, seq=%d, length=%d, total_bytes=%d",
		rep.Type, rep.SequenceNum, rep.Length, len(buf))
	log.Printf("DEBUG: Reply header: % x", buf[0:min(32, len(buf))])
	if len(buf) > 32 {
		log.Printf("DEBUG: Reply additional: % x", buf[32:min(48, len(buf))])
	}

	_, err := w.Write(buf)
	return err
}

// QueryExtensionRequest represents a QueryExtension request
type QueryExtensionRequest struct {
	Name string
}

// Parse parses a QueryExtension request from data
func (qer *QueryExtensionRequest) Parse(data []byte, bo binary.ByteOrder) error {
	if len(data) < 2 {
		return fmt.Errorf("insufficient data for QueryExtension")
	}

	nameLen := bo.Uint16(data[0:2])
	// data[2:4] is padding
	if len(data) < int(4+nameLen) {
		return fmt.Errorf("insufficient data for extension name")
	}

	qer.Name = string(data[4 : 4+nameLen])

	return nil
}

// QueryExtensionReply represents a QueryExtension reply
type QueryExtensionReply struct {
	Present     bool
	MajorOpcode uint8
	FirstEvent  uint8
	FirstError  uint8
}

// ToReply converts to a generic Reply
func (qer *QueryExtensionReply) ToReply(seqNum uint16, bo binary.ByteOrder) *Reply {
	data := make([]byte, 24)

	if qer.Present {
		data[0] = 1
	} else {
		data[0] = 0
	}

	data[1] = qer.MajorOpcode
	data[2] = qer.FirstEvent
	data[3] = qer.FirstError

	return &Reply{
		Type:        1, // Reply
		Detail:      0,
		SequenceNum: seqNum,
		Length:      0,
		Data:        data,
	}
}

// SecurityGenerateAuthRequest represents a SECURITY GenerateAuthorization request
type SecurityGenerateAuthRequest struct {
	TrustLevel uint8
	Timeout    uint32
	Group      uint32
}

// Value-mask bits for GenerateAuthorization
const (
	SecurityAuthTimeoutMask    = 1 << 0
	SecurityAuthTrustLevelMask = 1 << 1
	SecurityAuthGroupMask      = 1 << 2
)

// Parse parses a SecurityGenerateAuth request using value-mask format
func (sga *SecurityGenerateAuthRequest) Parse(data []byte, bo binary.ByteOrder) error {
	// Default values
	sga.TrustLevel = UNTRUSTED_LEVEL
	sga.Timeout = 0
	sga.Group = 0

	if len(data) < 4 {
		// If we have no data at all, use all defaults (valid for some clients)
		log.Printf("DEBUG: No value-mask, using all defaults")
		return nil
	}

	// Read value-mask
	valueMask := bo.Uint32(data[0:4])

	log.Printf("DEBUG: GenerateAuth value-mask: 0x%08x", valueMask)

	// Parse values based on mask
	// NOTE: If mask bit is set but data is missing, use default (some clients do this)
	offset := 4

	if valueMask&SecurityAuthTimeoutMask != 0 {
		if len(data) >= offset+4 {
			sga.Timeout = bo.Uint32(data[offset : offset+4])
			log.Printf("DEBUG: Parsed timeout: %d", sga.Timeout)
			offset += 4
		} else {
			log.Printf("DEBUG: Timeout bit set but no data, using default: %d", sga.Timeout)
		}
	}

	if valueMask&SecurityAuthTrustLevelMask != 0 {
		if len(data) >= offset+4 {
			sga.TrustLevel = uint8(bo.Uint32(data[offset : offset+4]))
			log.Printf("DEBUG: Parsed trust_level: %d", sga.TrustLevel)
			offset += 4
		} else {
			log.Printf("DEBUG: TrustLevel bit set but no data, using default: %d", sga.TrustLevel)
		}
	}

	if valueMask&SecurityAuthGroupMask != 0 {
		if len(data) >= offset+4 {
			sga.Group = bo.Uint32(data[offset : offset+4])
			log.Printf("DEBUG: Parsed group: %d", sga.Group)
			offset += 4
		} else {
			log.Printf("DEBUG: Group bit set but no data, using default: %d", sga.Group)
		}
	}

	return nil
}

// SecurityGenerateAuthReply represents a SECURITY GenerateAuthorization reply
type SecurityGenerateAuthReply struct {
	AuthID      uint32
	AuthData    []byte
	AuthDataLen uint16
}

// ToReply converts to a generic Reply
func (sga *SecurityGenerateAuthReply) ToReply(seqNum uint16, bo binary.ByteOrder) *Reply {
	// X11 Reply format:
	// Bytes 0-31: Standard reply header (type, detail, seq, length, then 24 bytes of data)
	// Bytes 32+: Additional data (specified by Length field in 4-byte units)

	log.Printf("DEBUG: ToReply - AuthID=%d, cookie_len=%d, AuthDataLen=%d", sga.AuthID, len(sga.AuthData), sga.AuthDataLen)
	log.Printf("DEBUG: Cookie data: % x", sga.AuthData)

	// The first 24 bytes of data in the standard reply header:
	replyData := make([]byte, 24)

	bo.PutUint32(replyData[0:4], sga.AuthID)      // Bytes 0-3: AuthID
	bo.PutUint16(replyData[4:6], sga.AuthDataLen) // Bytes 4-5: Data length
	// Bytes 6-23: padding (18 bytes)

	// The auth data goes in the additional data section after the 32-byte header
	additionalData := make([]byte, 0)
	if len(sga.AuthData) > 0 {
		// Pad auth data to 4-byte boundary
		padded := (len(sga.AuthData) + 3) & ^3
		log.Printf("DEBUG: Cookie padded length: %d", padded)
		additionalData = make([]byte, padded)
		copy(additionalData, sga.AuthData)
	}

	// Combine replyData and additional data
	allData := append(replyData, additionalData...)

	// Length field = number of 4-byte units in additional data (beyond the 24 bytes in header)
	additionalLength := uint32(len(additionalData) / 4)

	log.Printf("DEBUG: GenerateAuth reply - authID=%d, dataLen=%d, additionalData_len=%d, additionalUnits=%d",
		sga.AuthID, sga.AuthDataLen, len(additionalData), additionalLength)

	return &Reply{
		Type:        1,
		Detail:      0,
		SequenceNum: seqNum,
		Length:      additionalLength,
		Data:        allData,
	}
}

// Error represents an X11 error
type Error struct {
	Code        uint8
	SequenceNum uint16
	ResourceID  uint32
	MinorOpcode uint16
	MajorOpcode uint8
}

// Write writes the error to the writer
func (e *Error) Write(w io.Writer, bo binary.ByteOrder) error {
	buf := make([]byte, 32)
	buf[0] = 0 // Error type
	buf[1] = e.Code
	bo.PutUint16(buf[2:4], e.SequenceNum)
	bo.PutUint32(buf[4:8], e.ResourceID)
	bo.PutUint16(buf[8:10], e.MinorOpcode)
	buf[10] = e.MajorOpcode

	_, err := w.Write(buf)
	return err
}

// Helper functions
func appendUint16(buf []byte, v uint16, bo binary.ByteOrder) []byte {
	tmp := make([]byte, 2)
	bo.PutUint16(tmp, v)
	return append(buf, tmp...)
}

func appendUint32(buf []byte, v uint32, bo binary.ByteOrder) []byte {
	tmp := make([]byte, 4)
	bo.PutUint32(tmp, v)
	return append(buf, tmp...)
}

func padTo4(buf []byte) []byte {
	pad := (4 - (len(buf) % 4)) % 4
	for i := 0; i < pad; i++ {
		buf = append(buf, 0)
	}
	return buf
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
