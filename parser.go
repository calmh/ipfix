package ipfix

import (
	"bytes"
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
func (s *Session) ReadMessage() (msg *Message, err error) {
	defer func() {
		if r := recover(); r != nil {
			if _, ok := r.(runtime.Error); ok {
				panic(r)
			}

			msg = nil
			err = r.(error)
		}
	}()

	if pc, ok := s.reader.(readerFrom); ok {
		return s.readFromPacketConn(pc)
	} else {
		return s.readFromStream(s.reader)
	}
}

func (s *Session) readFromPacketConn(pc readerFrom) (msg *Message, err error) {
	if debug {
		log.Println("read from net.PacketConn")
	}

	buf := s.buffers.Get().([]byte)
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		return nil, err
	}
	r := bytes.NewBuffer(buf[:n])

	msg = &Message{}

	err = binary.Read(r, binary.BigEndian, &msg.Header)
	errorIf(err)
	if debug {
		log.Printf("read pktheader: %#v", msg.Header)
	}
	if msg.Header.Version != 10 {
		errorIf(ErrVersion)
	}
	errorIf(err)

	for r.Len() > 0 {
		trecs, drecs := s.readSet(r)
		msg.TemplateRecords = append(msg.TemplateRecords, trecs...)
		msg.DataRecords = append(msg.DataRecords, drecs...)
	}

	s.buffers.Put(buf)
	return
}

func (s *Session) readFromStream(sr io.Reader) (msg *Message, err error) {
	if debug {
		log.Println("read from io.Reader")
	}

	msg = &Message{}
	msg.DataRecords = make([]DataRecord, 0)
	msg.TemplateRecords = make([]TemplateRecord, 0)

	err = binary.Read(sr, binary.BigEndian, &msg.Header)
	errorIf(err)
	if debug {
		log.Printf("read pktheader: %#v", msg.Header)
	}
	if msg.Header.Version != 10 {
		errorIf(ErrVersion)
	}

	msgLen := int(msg.Header.Length) - msgHeaderLength
	if msgLen > 65535 {
		panic("unexpectedly long message, need to unoptimize")
	}
	msgSlice := s.buffers.Get().([]byte)[:msgLen]
	_, err = io.ReadFull(sr, msgSlice)
	errorIf(err)
	r := bytes.NewBuffer(msgSlice)

	for r.Len() > 0 {
		trecs, drecs := s.readSet(r)
		msg.TemplateRecords = append(msg.TemplateRecords, trecs...)
		msg.DataRecords = append(msg.DataRecords, drecs...)
	}

	s.buffers.Put(msgSlice[:cap(msgSlice)])

	return
}

func (s *Session) readSet(r *bytes.Buffer) (trecs []TemplateRecord, drecs []DataRecord) {
	trecs = make([]TemplateRecord, 0)
	drecs = make([]DataRecord, 0)

	setHdr := setHeader{}
	err := binary.Read(r, binary.BigEndian, &setHdr)
	if debug {
		log.Printf("read setheader: %#v", setHdr)
	}
	setEnd := r.Len() - int(setHdr.Length) + setHeaderLength
	errorIf(err)

	for r.Len() > setEnd {
		if r.Len()-setEnd < int(s.minRecord[setHdr.SetId]) {
			// Padding
			return
		} else if setHdr.SetId == 2 {
			if debug {
				log.Println("got template set")
			}

			// Template Set
			ts := s.readTemplateRecord(r)
			trecs = append(trecs, *ts)

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
			r.Read(make([]byte, int(setHdr.Length)-setHeaderLength))
		} else {
			if debug {
				log.Println("got data set for template", setHdr.SetId)
			}

			if tpl := s.templates[setHdr.SetId]; tpl != nil {
				// Data set
				ds := s.readDataRecord(r, tpl)
				ds.TemplateId = setHdr.SetId
				drecs = append(drecs, *ds)
			} else {
				if debug {
					log.Println("set", setHdr.SetId, "is unknown")
				}
				// Data set with unknown template
				// We can't trust set length, because we might be out of sync.
				// Consume rest of message.
				r.Read(make([]byte, r.Len()))
				return
			}
		}
	}

	return
}

func (s *Session) readDataRecord(r *bytes.Buffer, tpl []TemplateFieldSpecifier) *DataRecord {
	ds := DataRecord{}
	ds.Fields = make([][]byte, len(tpl))

	for i := range tpl {
		var bs []byte
		if tpl[i].Length == 65535 {
			bs = s.readVariableLength(r)
		} else {
			bs = s.readFixedLength(r, int(tpl[i].Length))
		}
		ds.Fields[i] = bs
	}

	return &ds
}

func (s *Session) readTemplateRecord(r *bytes.Buffer) *TemplateRecord {
	ts := TemplateRecord{}
	th := templateHeader{}
	err := binary.Read(r, binary.BigEndian, &th)
	errorIf(err)

	ts.TemplateId = th.TemplateId
	ts.FieldSpecifiers = make([]TemplateFieldSpecifier, th.FieldCount)
	for i := 0; i < int(th.FieldCount); i++ {
		f := TemplateFieldSpecifier{}
		err = binary.Read(r, binary.BigEndian, &f.FieldId)
		errorIf(err)
		err = binary.Read(r, binary.BigEndian, &f.Length)
		errorIf(err)
		if f.FieldId >= 0x8000 {
			f.FieldId -= 0x8000
			err = binary.Read(r, binary.BigEndian, &f.EnterpriseId)
			errorIf(err)
		}
		ts.FieldSpecifiers[i] = f
	}

	return &ts
}

func (s *Session) readFixedLength(r *bytes.Buffer, n int) []byte {
	bs := make([]byte, n)
	n1, err := r.Read(bs)
	errorIf(err)
	if n1 != n {
		panic(ErrRead)
	}
	return bs
}

func (s *Session) readVariableLength(r *bytes.Buffer) []byte {
	var l int

	var l0 uint8
	err := binary.Read(r, binary.BigEndian, &l0)
	errorIf(err)

	if l0 < 255 {
		l = int(l0)
	} else {
		var l1 uint16
		err := binary.Read(r, binary.BigEndian, &l1)
		errorIf(err)
		l = int(l1)
	}

	return s.readFixedLength(r, l)
}

func errorIf(err error) {
	if err != nil {
		panic(err)
	}
}
