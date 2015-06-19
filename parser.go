package ipfix

import (
	"encoding/binary"
	"errors"
	"io"
	"sync"
)

// The version field in IPFIX messages should always have the value 10. If it
// does not, you get this error. It's probably a sign of a bug in the parser or
// the exporter and that we have lost synchronization with the data stream.
// Reestablishing the session is the only way forward at this point.
var ErrVersion = errors.New("incorrect version field in message header - out of sync?")

// ErrRead is returned when a packet is not long enough for the field it is
// supposed to contain. This is a sign of an earlier read error or a corrupted
// packet.
var ErrRead = errors.New("short read - malformed packet?")

// A Message is the top level construct representing an IPFIX message. A well
// formed message contains one or more sets of data or template information.
// The array "DataRecords" stores the actual IPFIX data while "TemplateRecords"
// stores the corresponding template at the same index.
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
	DomainID       uint32
}

func (h *MessageHeader) unmarshal(bs []byte) {
	h.Version = binary.BigEndian.Uint16(bs[0:])
	h.Length = binary.BigEndian.Uint16(bs[2:])
	h.ExportTime = binary.BigEndian.Uint32(bs[2+2:])
	h.SequenceNumber = binary.BigEndian.Uint32(bs[2+2+4:])
	h.DomainID = binary.BigEndian.Uint32(bs[2+2+4+4:])
}

type setHeader struct {
	SetID  uint16
	Length uint16
}

type templateHeader struct {
	TemplateID uint16
	FieldCount uint16
}

// The DataRecord represents a single exported flow. The Fields each describe
// different aspects of the flow (source and destination address, counters,
// service, etc.).
type DataRecord struct {
	TemplateID uint16
	Fields     [][]byte
}

// The TemplateRecord describes a data template, as used by DataRecords.
type TemplateRecord struct {
	TemplateID      uint16
	FieldSpecifiers []TemplateFieldSpecifier
}

// The TemplateFieldSpecifier describes the ID and size of the corresponding
// Fields in a DataRecord.
type TemplateFieldSpecifier struct {
	EnterpriseID uint32
	FieldID      uint16
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
	msgHeaderLength = 2 + 2 + 4 + 4 + 4
	setHeaderLength = 2 + 2
)

// ParseReader extracts and returns one message from the IPFIX stream. As long
// as err is nil, further messages can be read from the stream. Errors are not
// recoverable -- once an error has been returned, ParseReader should not be
// called again on the same session.
func (s *Session) ParseReader(r io.Reader) (Message, error) {
	bs := s.buffers.Get().([]byte)
	bs, hdr, err := Read(r, bs)
	if err != nil {
		return Message{}, err
	}

	var msg Message
	msg.Header = hdr
	msg.TemplateRecords, msg.DataRecords, err = s.readBuffer(bs[msgHeaderLength:])
	s.buffers.Put(bs)
	return msg, err
}

// ParseBuffer extracts one message from the given buffer and returns it. Err
// is nil if the buffer could be parsed correctly. ParseBuffer is goroutine safe.
func (s *Session) ParseBuffer(bs []byte) (Message, error) {
	var msg Message
	var err error

	msg.Header.unmarshal(bs)
	msg.TemplateRecords, msg.DataRecords, err = s.readBuffer(bs[msgHeaderLength:])
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
		if trecs == nil {
			trecs = ts
		} else {
			trecs = append(trecs, ts...)
		}
		if drecs == nil {
			drecs = ds
		} else {
			drecs = append(drecs, ds...)
		}
	}
	return trecs, drecs, nil
}

func (s *Session) readSet(bs []byte) ([]TemplateRecord, []DataRecord, []byte, error) {
	var trecs []TemplateRecord
	var drecs []DataRecord

	setHdr := setHeader{}
	setHdr.SetID, bs = binary.BigEndian.Uint16(bs), bs[2:]
	setHdr.Length, bs = binary.BigEndian.Uint16(bs), bs[2:]
	setLen := int(setHdr.Length) - setHeaderLength
	if setLen > len(bs) {
		return nil, nil, nil, ErrRead
	}
	rest := bs[setLen:]

	s.mut.RLock()
	minLength := int(s.minRecord[setHdr.SetID])
	s.mut.RUnlock()

	for len(bs) > 0 {
		if len(bs) < minLength {
			// Padding
			return trecs, drecs, rest, nil
		} else if setHdr.SetID == 2 {
			// Template Set
			var tr TemplateRecord
			tr, bs = s.readTemplateRecord(bs)
			trecs = append(trecs, tr)

			s.registerTemplateRecord(tr)
		} else if setHdr.SetID == 3 {
			// Options Template Set, not handled
			bs = bs[len(bs):]
		} else {
			s.mut.RLock()
			tpl := s.templates[setHdr.SetID]
			s.mut.RUnlock()

			if tpl != nil {
				// Data set
				var ds DataRecord
				var err error
				ds, bs, err = s.readDataRecord(bs, tpl)
				if err != nil {
					return nil, nil, nil, err
				}
				ds.TemplateID = setHdr.SetID
				drecs = append(drecs, ds)
			} else {
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
	th.TemplateID, bs = binary.BigEndian.Uint16(bs), bs[2:]
	th.FieldCount, bs = binary.BigEndian.Uint16(bs), bs[2:]

	ts.TemplateID = th.TemplateID
	ts.FieldSpecifiers = make([]TemplateFieldSpecifier, th.FieldCount)
	for i := 0; i < int(th.FieldCount); i++ {
		f := TemplateFieldSpecifier{}
		f.FieldID, bs = binary.BigEndian.Uint16(bs), bs[2:]
		f.Length, bs = binary.BigEndian.Uint16(bs), bs[2:]
		if f.FieldID >= 0x8000 {
			f.FieldID -= 0x8000
			f.EnterpriseID, bs = binary.BigEndian.Uint32(bs), bs[4:]
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
	tid := tr.TemplateID

	// Calculate the minimum possible record length
	var minLength uint16
	for i := range tr.FieldSpecifiers {
		if tr.FieldSpecifiers[i].Length == 65535 {
			minLength++
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
