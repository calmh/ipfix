package ipfix

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
)

var NODATA = errors.New("not enough data to decode a full message")

type Message struct {
	Header       MessageHeader
	DataSets     []DataSet
	TemplateSets []TemplateSet
}

type MessageHeader struct {
	Version        uint16
	Length         uint16
	ExportTime     uint32
	SequenceNumber uint32
	DomainId       uint32
}

const MessageHeaderLength int = 2 + 2 + 4 + 4 + 4

/*

 MessageHeader
   SetHeader id=2
     TemplateHeader id=1234
       TemplateRecord
       TemplateRecord
       ...
     TemplateHeader id=2345
       TemplateRecord
       TemplateRecord
       ...
   SetHeader id=1234
       DataRecord
       DataRecord
       ...
       DataRecord
       DataRecord
       ...

*/

type SetHeader struct {
	SetId  uint16
	Length uint16
}

type DataSet struct {
	Records [][]byte
}

type FieldKey struct {
	EnterpriseId uint32
	FieldId      uint16
}

type TemplateSet struct {
	TemplateHeader TemplateHeader
	Records        []TemplateRecord
}

type TemplateHeader struct {
	TemplateId uint16
	FieldCount uint16
}

type TemplateRecord struct {
	EnterpriseId uint32
	FieldId      uint16
	Length       uint16
}

// Implements the io.Writer interface
type Session struct {
	buffer    *bytes.Buffer
	reader    *bufio.Reader
	templates [][]TemplateRecord
}

func NewSession() *Session {
	s := Session{}
	s.buffer = new(bytes.Buffer)
	s.reader = bufio.NewReader(s.buffer)
	s.templates = make([][]TemplateRecord, 65536)
	return &s
}

func (s *Session) Write(p []byte) (n int, err error) {
	return s.buffer.Write(p)
}

func (s *Session) peekMessageLength() (length int, err error) {
	b, err := s.reader.Peek(MessageHeaderLength)
	if err != nil {
		return
	}

	length = int(b[2])<<8 + int(b[3])

	return
}

func (s *Session) ReadMessage() (msg *Message, err error) {
	length, err := s.peekMessageLength()
	if err != nil {
		return
	}

	if length > s.reader.Buffered() {
		err = NODATA
		return
	}

	msg = &Message{}
	msg.DataSets = make([]DataSet, 0)
	msg.TemplateSets = make([]TemplateSet, 0)

	msgHdr := MessageHeader{}
	err = binary.Read(s.reader, binary.BigEndian, &msgHdr)
	if err != nil {
		return
	}
	read := binary.Size(msgHdr)
	msg.Header = msgHdr

	for read < length {
		setHdr := SetHeader{}
		err = binary.Read(s.reader, binary.BigEndian, &setHdr)
		setEndsAt := read + int(setHdr.Length)
		read += binary.Size(msgHdr)

		for read < setEndsAt {
			if setHdr.SetId == 2 {
				// Template Set
				ts, tsRead := s.readTemplateSet()
				read += tsRead
				msg.TemplateSets = append(msg.TemplateSets, *ts)

				tid := ts.TemplateHeader.TemplateId
				if s.templates[tid] == nil {
					s.templates[tid] = ts.Records
				}

			} else if setHdr.SetId == 3 {
				// Options Template Set - read the bytes and ignore it
				t := make([]byte, 0, setEndsAt-read)
				s.reader.Read(t)
				read = setEndsAt
			} else if tpl := s.templates[setHdr.SetId]; tpl != nil {
				// Data Set with known template
				ds := DataSet{}
				ds.Records = make([][]byte, len(tpl))
				for i := range tpl {
					var bs []byte
					if tpl[i].Length == 65535 {
						var bsRead int
						bs, bsRead = s.readVariableLength()
						read += bsRead
					} else {
						bs = make([]byte, tpl[i].Length)
						s.reader.Read(bs)
						read += int(tpl[i].Length)
					}
					ds.Records[i] = bs
				}
				msg.DataSets = append(msg.DataSets, ds)
			} else {
				// Unknown set - read the bytes and ignore
				t := make([]byte, 0, setEndsAt-read)
				s.reader.Read(t)
				read = setEndsAt
			}
		}
	}

	return
}

func (s *Session) readTemplateSet() (ts *TemplateSet, read int) {
	ts = &TemplateSet{}
	th := TemplateHeader{}
	binary.Read(s.reader, binary.BigEndian, &th)
	read = binary.Size(th)

	ts.Records = make([]TemplateRecord, th.FieldCount)
	for i := 0; i < int(th.FieldCount); i++ {
		f := TemplateRecord{}
		binary.Read(s.reader, binary.BigEndian, &f.FieldId)
		read += binary.Size(f.FieldId)
		binary.Read(s.reader, binary.BigEndian, &f.Length)
		read += binary.Size(f.Length)
		if f.FieldId >= 8192 {
			binary.Read(s.reader, binary.BigEndian, &f.EnterpriseId)
			read += binary.Size(f.EnterpriseId)
		}
		ts.Records[i] = f
	}

	ts.TemplateHeader = th
	return
}

func (s *Session) readVariableLength() ([]byte, int) {
	var l int
	var r int = 0
	var l0 uint8
	binary.Read(s.reader, binary.BigEndian, &l0)
	r += 1

	if l0 < 255 {
		l = int(l0)
	} else {
		var l1 uint16
		binary.Read(s.reader, binary.BigEndian, &l1)
	r += 2
		l = int(l1)
	}

	bs := make([]byte, l)
	s.reader.Read(bs)
	r += l
	return bs, r
}
