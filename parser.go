package ipfix

import (
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"runtime"
	"sync"
)

var debug = os.Getenv("IPFIXDEBUG") != ""

// The version field in IPFIX messages should always have the value 10. If it
// does not, you get this error. It's probably a sign of a bug in the parser or
// the exporter and that we have lost synchronization with the data stream.
// Reestablishing the session is the only way forward at this point.
var ErrVersion = errors.New("incorrect version field in message header - out of sync?")
var ErrRead = errors.New("short read - malformed packet?")

// A Message is the top level construct representing an IPFIX message. A well
// formed message contains one or more sets of data or template information.
type Message struct {
	Header          MessageHeader
	DataRecords     []DataRecord
	TemplateRecords []TemplateRecord
}

// The MessageHeader provides metadata for the entire Message. The sequence
// number and domain ID can be used to gain knowledge of messages lost on an
// unreliable transport such as UDP.
type MessageHeader struct {
	Version        uint16 // Always 0x0a
	Length         uint16
	ExportTime     uint32 // Epoch seconds
	SequenceNumber uint32
	DomainId       uint32
}

func (h *MessageHeader) Unmarshal(bs []byte) {
	h.Version = binary.BigEndian.Uint16(bs[0:])
	h.Length = binary.BigEndian.Uint16(bs[2:])
	h.ExportTime = binary.BigEndian.Uint32(bs[2+2:])
	h.SequenceNumber = binary.BigEndian.Uint32(bs[2+2+4:])
	h.DomainId = binary.BigEndian.Uint32(bs[2+2+4+4:])
}

type setHeader struct {
	SetId  uint16
	Length uint16
}

type templateHeader struct {
	TemplateId uint16
	FieldCount uint16
}

// The DataRecord represents a single exported flow. The Fields each describe
// different aspects of the flow (source and destination address, counters,
// service, etc.).
type DataRecord struct {
	TemplateId uint16
	Fields     [][]byte
}

// The TemplateRecord describes a data template, as used by DataRecords.
type TemplateRecord struct {
	TemplateId      uint16
	FieldSpecifiers []TemplateFieldSpecifier
}

// The TemplateFieldSpecifier describes the ID and size of the corresponding
// Fields in a DataRecord.
type TemplateFieldSpecifier struct {
	EnterpriseId uint32
	FieldId      uint16
	Length       uint16
}

// The Session is the context for IPFIX messages.
type Session struct {
	templates [][]TemplateFieldSpecifier
	reader    io.Reader
	minRecord []uint16
	buffers   *sync.Pool
}

// NewSession initializes a new Session based on the provided io.Reader.
func NewSession(reader io.Reader) *Session {
	s := Session{}
	s.templates = make([][]TemplateFieldSpecifier, 65536)
	s.reader = reader
	s.minRecord = make([]uint16, 65536)
	s.buffers = &sync.Pool{
		New: func() interface{} {
			return make([]byte, 65536)
		},
	}
	return &s
}

var msgHeaderLength = binary.Size(MessageHeader{})
var setHeaderLength = binary.Size(setHeader{})
var templateHeaderLength = binary.Size(templateHeader{})

// readerFrom is the relevant part of a net.PacketConn
type readerFrom interface {
	ReadFrom([]byte) (int, net.Addr, error)
}

// ReadMessage extracts and returns one message from the IPFIX stream. As long
// as err is nil, further messages can be read from the stream. Errors are not
// recoverable -- once an error has been returned, ReadMessage should not be
// called again on the same session.
func (s *Session) ReadMessage() (msg Message, err error) {
	defer func() {
		if r := recover(); r != nil {
			if _, ok := r.(runtime.Error); ok {
				panic(r)
			}

			err = r.(error)
		}
	}()

	if pc, ok := s.reader.(readerFrom); ok {
		return s.readFromPacketConn(pc)
	} else {
		return s.readFromStream(s.reader)
	}
}

func (s *Session) readFromPacketConn(pc readerFrom) (Message, error) {
	if debug {
		log.Println("read from net.PacketConn")
	}

	buf := s.buffers.Get().([]byte)
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		return Message{}, err
	}
	bs := buf[:n]

	var msg Message
	msg.Header.Unmarshal(bs)
	bs = bs[msgHeaderLength:]
	if debug {
		log.Printf("read pktheader: %#v", msg.Header)
	}
	if msg.Header.Version != 10 {
		return Message{}, ErrVersion
	}

	msg.TemplateRecords, msg.DataRecords = s.readBuffer(bs)

	s.buffers.Put(buf)
	return msg, nil
}

func (s *Session) readFromStream(sr io.Reader) (Message, error) {
	if debug {
		log.Println("read from io.Reader")
	}

	buf := s.buffers.Get().([]byte)
	_, err := io.ReadFull(sr, buf[:msgHeaderLength])
	if err != nil {
		panic(err)
	}

	var msg Message
	msg.Header.Unmarshal(buf)

	if debug {
		log.Printf("read pktheader: %#v", msg.Header)
	}
	if msg.Header.Version != 10 {
		return Message{}, ErrVersion
	}

	msgLen := int(msg.Header.Length) - msgHeaderLength
	if msgLen > 65535 {
		panic("unexpectedly long message, need to unoptimize")
	}
	msgSlice := buf[:msgLen]
	_, err = io.ReadFull(sr, msgSlice)
	if err != nil {
		return Message{}, err
	}

	msg.TemplateRecords, msg.DataRecords = s.readBuffer(msgSlice)

	s.buffers.Put(buf)

	return msg, nil
}

func (s *Session) readBuffer(bs []byte) ([]TemplateRecord, []DataRecord) {
	var ts, trecs []TemplateRecord
	var ds, drecs []DataRecord
	for len(bs) > 0 {
		ts, ds, bs = s.readSet(bs)
		trecs = append(trecs, ts...)
		drecs = append(drecs, ds...)
	}
	return trecs, drecs
}

func (s *Session) readSet(bs []byte) ([]TemplateRecord, []DataRecord, []byte) {
	var trecs []TemplateRecord
	var drecs []DataRecord

	setHdr := setHeader{}
	setHdr.SetId, bs = binary.BigEndian.Uint16(bs), bs[2:]
	setHdr.Length, bs = binary.BigEndian.Uint16(bs), bs[2:]
	if debug {
		log.Printf("read setheader: %#v", setHdr)
		log.Println(setHdr.Length, len(bs))
	}
	rest := bs[int(setHdr.Length)-setHeaderLength:]

	for len(bs) > 0 {
		if len(bs) < int(s.minRecord[setHdr.SetId]) {
			// Padding
			return trecs, drecs, rest
		} else if setHdr.SetId == 2 {
			if debug {
				log.Println("got template set")
			}

			// Template Set
			var ts TemplateRecord
			ts, bs = s.readTemplateRecord(bs)
			trecs = append(trecs, ts)

			if debug {
				log.Println("template for set", ts.TemplateId)
				for _, t := range ts.FieldSpecifiers {
					log.Printf("    %v", t)
				}
			}

			// Update the template cache
			tid := ts.TemplateId
			if len(ts.FieldSpecifiers) == 0 {
				// Set was withdrawn
				s.templates[tid] = nil
			} else {
				s.templates[tid] = ts.FieldSpecifiers
			}

			// Update the minimum record length cache
			var minLength uint16
			for i := range ts.FieldSpecifiers {
				if ts.FieldSpecifiers[i].Length == 65535 {
					minLength += 1
				} else {
					minLength += ts.FieldSpecifiers[i].Length
				}
			}
			s.minRecord[tid] = minLength
		} else if setHdr.SetId == 3 {
			if debug {
				log.Println("got options template set, unhandled")
			}

			// Options Template Set, not handled
			bs = bs[len(bs):]
		} else {
			if debug {
				log.Println("got data set for template", setHdr.SetId)
			}

			if tpl := s.templates[setHdr.SetId]; tpl != nil {
				// Data set
				var ds DataRecord
				ds, bs = s.readDataRecord(bs, tpl)
				ds.TemplateId = setHdr.SetId
				drecs = append(drecs, ds)
			} else {
				if debug {
					log.Println("set", setHdr.SetId, "is unknown")
				}
				// Data set with unknown template
				// We can't trust set length, because we might be out of sync.
				// Consume rest of message.
				return nil, nil, nil
			}
		}
	}

	return trecs, drecs, rest
}

func (s *Session) readDataRecord(bs []byte, tpl []TemplateFieldSpecifier) (DataRecord, []byte) {
	ds := DataRecord{}
	ds.Fields = make([][]byte, len(tpl))

	for i := range tpl {
		var val []byte
		if tpl[i].Length == 65535 {
			val, bs = s.readVariableLength(bs)
		} else {
			val, bs = s.readFixedLength(bs, int(tpl[i].Length))
		}
		ds.Fields[i] = val
	}

	return ds, bs
}

func (s *Session) readTemplateRecord(bs []byte) (TemplateRecord, []byte) {
	ts := TemplateRecord{}
	th := templateHeader{}
	th.TemplateId, bs = binary.BigEndian.Uint16(bs), bs[2:]
	th.FieldCount, bs = binary.BigEndian.Uint16(bs), bs[2:]

	ts.TemplateId = th.TemplateId
	ts.FieldSpecifiers = make([]TemplateFieldSpecifier, th.FieldCount)
	for i := 0; i < int(th.FieldCount); i++ {
		f := TemplateFieldSpecifier{}
		f.FieldId, bs = binary.BigEndian.Uint16(bs), bs[2:]
		f.Length, bs = binary.BigEndian.Uint16(bs), bs[2:]
		if f.FieldId >= 0x8000 {
			f.FieldId -= 0x8000
			f.EnterpriseId, bs = binary.BigEndian.Uint32(bs), bs[4:]
		}
		ts.FieldSpecifiers[i] = f
	}

	return ts, bs
}

func (s *Session) readVariableLength(bs []byte) (val, rest []byte) {
	var l int

	l0, bs := bs[0], bs[1:]
	if l0 < 255 {
		l = int(l0)
	} else {
		l, bs = int(binary.BigEndian.Uint16(bs)), bs[2:]
	}

	return s.readFixedLength(bs, l)
}

func (s *Session) readFixedLength(bs []byte, l int) (val, rest []byte) {
	if l > len(bs) {
		panic(ErrRead)
	}
	val = make([]byte, l)
	copy(val, bs)
	return val, bs[l:]
}
