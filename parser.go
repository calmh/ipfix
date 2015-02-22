package ipfix

import (
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"os"
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

func (h *MessageHeader) unmarshal(bs []byte) {
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
	buffers *sync.Pool

	mut       sync.RWMutex
	templates [][]TemplateFieldSpecifier
	minRecord []uint16
}

// NewSession initializes a new Session based on the provided io.Reader.
func NewSession() *Session {
	s := Session{}
	s.templates = make([][]TemplateFieldSpecifier, 65536)
	s.minRecord = make([]uint16, 65536)
	s.buffers = &sync.Pool{
		New: func() interface{} {
			return make([]byte, 65536)
		},
	}
	return &s
}

const (
	msgHeaderLength      = 2 + 2 + 4 + 4 + 4
	setHeaderLength      = 2 + 2
	templateHeaderLength = 2 + 2
)

// readerFrom is the relevant part of a net.PacketConn
type readerFrom interface {
	ReadFrom([]byte) (int, net.Addr, error)
}

// ReadMessage extracts and returns one message from the IPFIX stream. As long
// as err is nil, further messages can be read from the stream. Errors are not
// recoverable -- once an error has been returned, ReadMessage should not be
// called again on the same session.
func (s *Session) ReadMessage(reader io.Reader) (msg Message, err error) {
	if pc, ok := reader.(readerFrom); ok {
		return s.readFromPacketConn(pc)
	} else {
		return s.readFromStream(reader)
	}
}

// ParseBuffer extracts one message from the given buffer and returns it. Err
// is nil if the buffer could be parsed correctly. ParseBuffer is goroutine safe.
func (s *Session) ParseBuffer(bs []byte) (Message, error) {
	var msg Message

	msg.Header.unmarshal(bs)
	bs = bs[msgHeaderLength:]
	if debug {
		log.Printf("read pktheader: %#v", msg.Header)
	}
	if msg.Header.Version != 10 {
		return Message{}, ErrVersion
	}

	var err error
	msg.TemplateRecords, msg.DataRecords, err = s.readBuffer(bs)
	return msg, err
}

func (s *Session) readFromPacketConn(pc readerFrom) (Message, error) {
	if debug {
		log.Println("read from net.PacketConn")
	}

	buf := s.buffers.Get().([]byte)
	defer s.buffers.Put(buf)

	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		return Message{}, err
	}
	bs := buf[:n]

	return s.ParseBuffer(bs)
}

func (s *Session) readFromStream(sr io.Reader) (Message, error) {
	if debug {
		log.Println("read from io.Reader")
	}

	buf := s.buffers.Get().([]byte)
	_, err := io.ReadFull(sr, buf[:msgHeaderLength])
	if err != nil {
		return Message{}, err
	}

	var msg Message
	msg.Header.unmarshal(buf)

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

	msg.TemplateRecords, msg.DataRecords, err = s.readBuffer(msgSlice)

	s.buffers.Put(buf)

	return msg, err
}

func (s *Session) readBuffer(bs []byte) ([]TemplateRecord, []DataRecord, error) {
	var ts, trecs []TemplateRecord
	var ds, drecs []DataRecord
	var err error
	for len(bs) > 0 {
		ts, ds, bs, err = s.readSet(bs)
		if err != nil {
			return nil, nil, err
		}
		trecs = append(trecs, ts...)
		drecs = append(drecs, ds...)
	}
	return trecs, drecs, nil
}

func (s *Session) readSet(bs []byte) ([]TemplateRecord, []DataRecord, []byte, error) {
	var trecs []TemplateRecord
	var drecs []DataRecord

	setHdr := setHeader{}
	setHdr.SetId, bs = binary.BigEndian.Uint16(bs), bs[2:]
	setHdr.Length, bs = binary.BigEndian.Uint16(bs), bs[2:]
	if debug {
		log.Printf("read setheader: %#v", setHdr)
	}
	rest := bs[int(setHdr.Length)-setHeaderLength:]

	s.mut.RLock()
	minLength := int(s.minRecord[setHdr.SetId])
	s.mut.RUnlock()

	for len(bs) > 0 {
		if len(bs) < minLength {
			// Padding
			return trecs, drecs, rest, nil
		} else if setHdr.SetId == 2 {
			if debug {
				log.Println("got template set")
			}

			// Template Set
			var tr TemplateRecord
			tr, bs = s.readTemplateRecord(bs)
			trecs = append(trecs, tr)

			if debug {
				log.Println("template for set", tr.TemplateId)
				for _, t := range tr.FieldSpecifiers {
					log.Printf("    %v", t)
				}
			}

			s.registerTemplateRecord(tr)
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

			s.mut.RLock()
			tpl := s.templates[setHdr.SetId]
			s.mut.RUnlock()

			if tpl != nil {
				// Data set
				var ds DataRecord
				var err error
				ds, bs, err = s.readDataRecord(bs, tpl)
				if err != nil {
					return nil, nil, nil, err
				}
				ds.TemplateId = setHdr.SetId
				drecs = append(drecs, ds)
			} else {
				if debug {
					log.Println("set", setHdr.SetId, "is unknown")
				}
				// Data set with unknown template
				// We can't trust set length, because we might be out of sync.
				// Consume rest of message.
				return trecs, drecs, nil, nil
			}
		}
	}

	return trecs, drecs, rest, nil
}

func (s *Session) readDataRecord(bs []byte, tpl []TemplateFieldSpecifier) (DataRecord, []byte, error) {
	ds := DataRecord{}
	ds.Fields = make([][]byte, len(tpl))

	var err error
	total := 0
	for i := range tpl {
		var val []byte
		if tpl[i].Length == 65535 {
			val, bs, err = s.readVariableLength(bs)
			if err != nil {
				return DataRecord{}, nil, err
			}
		} else {
			l := int(tpl[i].Length)
			val, bs = bs[:l], bs[l:]
		}
		ds.Fields[i] = val
		total += len(val)
	}

	// The loop above keeps slices of the original buffer. But that buffer
	// will be recycled so we need to copy them to separate storage. It's more
	// efficient to do it this way, with a single allocation at the end that
	// doing individual allocations along the way.

	cp := make([]byte, total)
	next := 0
	for i := range ds.Fields {
		ln := copy(cp[next:], ds.Fields[i])
		ds.Fields[i] = cp[next : next+ln]
		next += ln
	}

	return ds, bs, nil
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

func (s *Session) readVariableLength(bs []byte) (val, rest []byte, err error) {
	var l int

	l0, bs := bs[0], bs[1:]
	if l0 < 255 {
		l = int(l0)
	} else {
		l, bs = int(binary.BigEndian.Uint16(bs)), bs[2:]
	}

	if l > len(bs) {
		return nil, nil, io.EOF
	}
	return bs[:l], bs[l:], nil
}

func (s *Session) registerTemplateRecord(tr TemplateRecord) {
	// Update the template cache
	tid := tr.TemplateId

	// Calculate the minimum possible record length
	var minLength uint16
	for i := range tr.FieldSpecifiers {
		if tr.FieldSpecifiers[i].Length == 65535 {
			minLength += 1
		} else {
			minLength += tr.FieldSpecifiers[i].Length
		}
	}

	// Update templates and minimum record cache
	s.mut.Lock()
	if len(tr.FieldSpecifiers) == 0 {
		// Set was withdrawn
		s.templates[tid] = nil
	} else {
		s.templates[tid] = tr.FieldSpecifiers
	}
	s.minRecord[tid] = minLength
	s.mut.Unlock()
}
