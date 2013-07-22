package ipfix

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
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
	reader     *bufio.Reader
	minRecord  []uint16
	dictionary dictionary
}

// NewSession initializes a new Session based on the provided io.Reader.
func NewSession(reader io.Reader) *Session {
	s := Session{}
	s.templates = make([][]TemplateRecord, 65536)
	s.reader = bufio.NewReaderSize(reader, 32768)
	s.minRecord = make([]uint16, 65536)
	s.dictionary = builtinDictionary
	return &s
}

// ReadMessage extracts and returns one message from the IPFIX stream. As long
// as err is nil, further messages can be read from the stream. Errors are not
// recoverable -- once an error has been returned, ReadMessage should not be
// called again on the same session.
func (s *Session) ReadMessage() (msg *Message, err error) {
	msg = &Message{}
	msg.DataSets = make([]DataSet, 0)
	msg.TemplateSets = make([]TemplateSet, 0)

	msgHdr := MessageHeader{}
	err = binary.Read(s.reader, binary.BigEndian, &msgHdr)
	if err != nil {
		return
	}
	if msgHdr.Version != 10 {
		err = ErrVersion
		return
	}
	read := binary.Size(msgHdr)
	msg.Header = msgHdr

	for read < int(msgHdr.Length) {
		tsets, dsets, tr, err := s.readSet()
		if err != nil {
			return nil, err
		}
		read += tr
		msg.TemplateSets = append(msg.TemplateSets, tsets...)
		msg.DataSets = append(msg.DataSets, dsets...)
	}
	return
}

func (s *Session) readSet() (tsets []TemplateSet, dsets []DataSet, read int, err error) {
	tsets = make([]TemplateSet, 0)
	dsets = make([]DataSet, 0)

	setHdr := setHeader{}
	err = binary.Read(s.reader, binary.BigEndian, &setHdr)
	if err != nil {
		return
	}
	read += binary.Size(setHdr)

	end := int(setHdr.Length)
	for read < end {
		if end-read < int(s.minRecord[setHdr.SetId]) {
			// Padding
			_, err = io.ReadFull(s.reader, make([]byte, end-read))
			if err != nil {
				return
			}
			read += end - read
		} else if setHdr.SetId == 2 {
			// Template Set
			var ts *TemplateSet
			var tsRead int
			ts, tsRead, err = s.readTemplateSet()
			if err != nil {
				return
			}
			read += tsRead
			tsets = append(tsets, *ts)

			tid := ts.TemplateId
			s.templates[tid] = ts.Records

			var minLength uint16
			for i := range ts.Records {
				if ts.Records[i].Length == 65535 {
					minLength += 1
				} else {
					minLength += ts.Records[i].Length
				}
				s.minRecord[i] = minLength
			}
		} else if setHdr.SetId == 3 {
			// Options Template Set, not handled
			_, err = io.ReadFull(s.reader, make([]byte, end-read))
			if err != nil {
				return
			}
			read += end - read
		} else {
			// Data Set
			ds := DataSet{}
			ds.TemplateId = setHdr.SetId

			if tpl := s.templates[setHdr.SetId]; tpl != nil {
				ds.Records = make([][]byte, len(tpl))
				for i := range tpl {
					var bs []byte
					if tpl[i].Length == 65535 {
						var bsRead int
						bs, bsRead, err = s.readVariableLength()
						if err != nil {
							return
						}
						read += bsRead
					} else {
						bs = make([]byte, tpl[i].Length)
						_, err = io.ReadFull(s.reader, bs)
						if err != nil {
							return
						}
						read += len(bs)
					}
					ds.Records[i] = bs
				}
			} else {
				// Data set with unknown template
				_, err = io.ReadFull(s.reader, make([]byte, end-read))
				if err != nil {
					return
				}
				read += end - read
			}

			dsets = append(dsets, ds)
		}
	}
	return
}

func (s *Session) readTemplateSet() (ts *TemplateSet, read int, err error) {
	ts = &TemplateSet{}
	th := templateHeader{}
	err = binary.Read(s.reader, binary.BigEndian, &th)
	if err != nil {
		return
	}
	read = binary.Size(th)

	ts.TemplateId = th.TemplateId
	ts.Records = make([]TemplateRecord, th.FieldCount)
	for i := 0; i < int(th.FieldCount); i++ {
		f := TemplateRecord{}
		err = binary.Read(s.reader, binary.BigEndian, &f.FieldId)
		if err != nil {
			return
		}
		read += binary.Size(f.FieldId)
		err = binary.Read(s.reader, binary.BigEndian, &f.Length)
		if err != nil {
			return
		}
		read += binary.Size(f.Length)
		if f.FieldId >= 0x8000 {
			f.FieldId -= 0x8000
			err = binary.Read(s.reader, binary.BigEndian, &f.EnterpriseId)
			if err != nil {
				return
			}
			read += binary.Size(f.EnterpriseId)
		}
		ts.Records[i] = f
	}

	return
}

// Reads a variable length information element. Returns a slice with the data
// in it, the total number of bytes read and possibly an error.
func (s *Session) readVariableLength() (bs []byte, r int, err error) {
	var l int

	var l0 uint8
	err = binary.Read(s.reader, binary.BigEndian, &l0)
	if err != nil {
		return
	}
	r += 1

	if l0 < 255 {
		l = int(l0)
	} else {
		var l1 uint16
		err = binary.Read(s.reader, binary.BigEndian, &l1)
		if err != nil {
			return
		}
		r += 2
		l = int(l1)
	}

	bs = make([]byte, l)
	_, err = io.ReadFull(s.reader, bs)
	if err != nil {
		return
	}
	r += len(bs)

	return
}
