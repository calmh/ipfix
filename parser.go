package ipfix

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
)

var ErrVersion = errors.New("incorrect version field in message header - out of sync?")

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

type SetHeader struct {
	SetId  uint16
	Length uint16
}

const SetHeaderLength = 2 + 2

type DataSet struct {
	TemplateId uint16
	Records    [][]byte
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

type Session struct {
	Templates [][]TemplateRecord
	reader    *bufio.Reader
	minRecord []uint16
}

func NewSession(reader io.Reader) *Session {
	s := Session{}
	s.Templates = make([][]TemplateRecord, 65536)
	s.reader = bufio.NewReaderSize(reader, 32768)
	s.minRecord = make([]uint16, 65536)
	return &s
}

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
	read := MessageHeaderLength
	msg.Header = msgHdr

	for read < int(msgHdr.Length) {
		setHdr := SetHeader{}
		err = binary.Read(s.reader, binary.BigEndian, &setHdr)
		if err != nil {
			return
		}
		setEndsAt := read + int(setHdr.Length)
		read += SetHeaderLength

		for read < setEndsAt {
			if setEndsAt-read < int(s.minRecord[setHdr.SetId]) {
				// Padding
				_, err = io.ReadFull(s.reader, make([]byte, setEndsAt-read))
				if err != nil {
					return
				}
				read += setEndsAt - read
			} else if setHdr.SetId == 2 {
				// Template Set
				var ts *TemplateSet
				var tsRead int
				ts, tsRead, err = s.readTemplateSet()
				if err != nil {
					return
				}
				read += tsRead
				msg.TemplateSets = append(msg.TemplateSets, *ts)

				tid := ts.TemplateHeader.TemplateId
				s.Templates[tid] = ts.Records

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
				_, err = io.ReadFull(s.reader, make([]byte, setEndsAt-read))
				if err != nil {
					return
				}
				read += setEndsAt - read
			} else {
				// Data Set
				ds := DataSet{}
				ds.TemplateId = setHdr.SetId

				if tpl := s.Templates[setHdr.SetId]; tpl != nil {
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
					_, err = io.ReadFull(s.reader, make([]byte, setEndsAt-read))
					if err != nil {
						return
					}
					read += setEndsAt - read
				}

				msg.DataSets = append(msg.DataSets, ds)
			}
		}
	}
	return
}

func (s *Session) readTemplateSet() (ts *TemplateSet, read int, err error) {
	ts = &TemplateSet{}
	th := TemplateHeader{}
	err = binary.Read(s.reader, binary.BigEndian, &th)
	if err != nil {
		return
	}
	read = binary.Size(th)

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
		if f.FieldId >= 8192 {
			err = binary.Read(s.reader, binary.BigEndian, &f.EnterpriseId)
			if err != nil {
				return
			}
			read += binary.Size(f.EnterpriseId)
		}
		ts.Records[i] = f
	}

	ts.TemplateHeader = th
	return
}

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
