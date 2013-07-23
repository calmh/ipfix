package ipfix

import (
	"encoding/binary"
	"errors"
	"io"
	"runtime"
)

// The version field in IPFIX messages should always have the value 10. If it
// does not, you get this error. It's probably a sign of a bug in the parser or
// the exporter and that we have lost synchronization with the data stream.
// Reestablishing the session is the only way forward at this point.
var ErrVersion = errors.New("incorrect version field in message header - out of sync?")

// A Message is the top level construct representing an IPFIX message. A well
// formed message contains one or more sets of data or template information.
type Message struct {
	Header       MessageHeader
	DataSets     []DataSet
	TemplateSets []TemplateSet
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

// The DataSet represents a single exported flow. The Records each describe
// different aspects of the flow (source and destination address, counters,
// service, etc.).
type DataSet struct {
	TemplateId uint16
	Records    [][]byte
}

// The TemplateSet describes a data template, as used by DataSets.
type TemplateSet struct {
	TemplateId uint16
	Records    []TemplateRecord
}

// The TemplateRecord describes the ID and size of the corresponding Records in a DataSet.
type TemplateRecord struct {
	EnterpriseId uint32
	FieldId      uint16
	Length       uint16
}

// The Session is the context for IPFIX messages.
type Session struct {
	templates  [][]TemplateRecord
	reader     io.Reader
	minRecord  []uint16
	dictionary dictionary
	bytesRead  int
}

// NewSession initializes a new Session based on the provided io.Reader.
func NewSession(reader io.Reader) *Session {
	s := Session{}
	s.templates = make([][]TemplateRecord, 65536)
	s.reader = reader
	s.minRecord = make([]uint16, 65536)
	s.dictionary = builtinDictionary
	return &s
}

var msgHeaderLength = binary.Size(MessageHeader{})
var setHeaderLength = binary.Size(setHeader{})
var templateHeaderLength = binary.Size(templateHeader{})

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

	s.bytesRead = 0
	msg = &Message{}
	msg.DataSets = make([]DataSet, 0)
	msg.TemplateSets = make([]TemplateSet, 0)

	msgHdr := MessageHeader{}
	err = binary.Read(s.reader, binary.BigEndian, &msgHdr)
	s.errorIf(err)
	if msgHdr.Version != 10 {
		s.errorIf(ErrVersion)
	}
	s.bytesRead += msgHeaderLength
	msg.Header = msgHdr

	for s.bytesRead < int(msgHdr.Length) {
		tsets, dsets := s.readSet()
		msg.TemplateSets = append(msg.TemplateSets, tsets...)
		msg.DataSets = append(msg.DataSets, dsets...)
	}

	return
}

func (s *Session) errorIf(err error) {
	if err != nil {
		panic(err)
	}
}

func (s *Session) readSet() ([]TemplateSet, []DataSet) {
	tsets := make([]TemplateSet, 0)
	dsets := make([]DataSet, 0)

	setHdr := setHeader{}
	err := binary.Read(s.reader, binary.BigEndian, &setHdr)
	s.errorIf(err)

	end := s.bytesRead + int(setHdr.Length)
	s.bytesRead += setHeaderLength

	for s.bytesRead < end {
		if end-s.bytesRead < int(s.minRecord[setHdr.SetId]) {
			// Padding
			_, err = io.ReadFull(s.reader, make([]byte, end-s.bytesRead))
			s.errorIf(err)
			s.bytesRead = end
		} else if setHdr.SetId == 2 {
			// Template Set
			ts := s.readTemplateSet()
			tsets = append(tsets, *ts)

			// Update the template cache
			tid := ts.TemplateId
			if len(ts.Records) == 0 {
				// Set was withdrawn
				s.templates[tid] = nil
			} else {
				s.templates[tid] = ts.Records
			}

			// Update the minimum record length cache
			var minLength uint16
			for i := range ts.Records {
				if ts.Records[i].Length == 65535 {
					minLength += 1
				} else {
					minLength += ts.Records[i].Length
				}
			}
			s.minRecord[tid] = minLength
		} else if setHdr.SetId == 3 {
			// Options Template Set, not handled
			s.readFull(end - s.bytesRead)
		} else {
			if tpl := s.templates[setHdr.SetId]; tpl != nil {
				// Data set
				ds := s.readDataSet(tpl)
				ds.TemplateId = setHdr.SetId
				dsets = append(dsets, *ds)
			} else {
				// Data set with unknown template
				s.readFull(end - s.bytesRead)
			}
		}
	}

	return tsets, dsets
}

func (s *Session) readFull(n int) []byte {
	bs := make([]byte, n)
	_, err := io.ReadFull(s.reader, bs)
	s.errorIf(err)
	s.bytesRead += len(bs)
	return bs
}

func (s *Session) readDataSet(tpl []TemplateRecord) *DataSet {
	ds := DataSet{}
	ds.Records = make([][]byte, len(tpl))

	for i := range tpl {
		var bs []byte
		if tpl[i].Length == 65535 {
			bs = s.readVariableLength()
		} else {
			bs = s.readFull(int(tpl[i].Length))
		}
		ds.Records[i] = bs
	}

	return &ds
}

func (s *Session) readTemplateSet() *TemplateSet {
	ts := TemplateSet{}
	th := templateHeader{}
	err := binary.Read(s.reader, binary.BigEndian, &th)
	s.errorIf(err)
	s.bytesRead += templateHeaderLength

	ts.TemplateId = th.TemplateId
	ts.Records = make([]TemplateRecord, th.FieldCount)
	for i := 0; i < int(th.FieldCount); i++ {
		f := TemplateRecord{}
		err = binary.Read(s.reader, binary.BigEndian, &f.FieldId)
		s.errorIf(err)
		s.bytesRead += 2
		err = binary.Read(s.reader, binary.BigEndian, &f.Length)
		s.errorIf(err)
		s.bytesRead += 2
		if f.FieldId >= 0x8000 {
			f.FieldId -= 0x8000
			err = binary.Read(s.reader, binary.BigEndian, &f.EnterpriseId)
			s.errorIf(err)
			s.bytesRead += 4
		}
		ts.Records[i] = f
	}

	return &ts
}

func (s *Session) readVariableLength() []byte {
	var l int

	var l0 uint8
	err := binary.Read(s.reader, binary.BigEndian, &l0)
	s.errorIf(err)
	s.bytesRead += 1

	if l0 < 255 {
		l = int(l0)
	} else {
		var l1 uint16
		err = binary.Read(s.reader, binary.BigEndian, &l1)
		s.errorIf(err)
		s.bytesRead += 2
		l = int(l1)
	}

	return s.readFull(l)
}
