package ipfix

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// IPFIX type of an Information Element ("Field").
type FieldType string

// The available field types as defined by RFC 5102.
const (
	Uint8                FieldType = "unsigned8"
	Uint16               FieldType = "unsigned16"
	Uint32               FieldType = "unsigned32"
	Uint64               FieldType = "unsigned64"
	Int8                 FieldType = "signed8"
	Int16                FieldType = "signed16"
	Int32                FieldType = "signed32"
	Int64                FieldType = "signed64"
	Float32              FieldType = "float32"
	Float64              FieldType = "float64"
	Boolean              FieldType = "boolean"
	MacAddress           FieldType = "macAddress"
	OctetArray           FieldType = "octetArray"
	String               FieldType = "string"
	DateTimeSeconds      FieldType = "dateTimeSeconds"
	DateTimeMilliseconds FieldType = "dateTimeMilliseconds"
	DateTimeMicroseconds FieldType = "dateTimeMicroseconds"
	DateTimeNanoseconds  FieldType = "dateTimeNanoseconds"
	Ipv4Address          FieldType = "ipv4Address"
	Ipv6Address          FieldType = "ipv6Address"
)

// DictionaryEntry provied a mapping between an (Enterprise, Field) pair and a Name and Type.
type DictionaryEntry struct {
	Name         string
	FieldId      uint16
	EnterpriseId uint32
	Type         FieldType
}

type dictionaryKey struct {
	EnterpriseId uint32
	FieldId      uint16
}

type fieldDictionary map[dictionaryKey]DictionaryEntry

// An InterpretedField is a field with the field name filled in and the value
// converted to the appropriate type.  If this is not possible (because the
// name and type of the field is unknown at the time of interpretation), Name
// will be the empty string, Value will be a nil interface and RawValue will
// contain the original bytes.
type InterpretedField struct {
	Name         string
	EnterpriseId uint32
	FieldId      uint16
	Value        interface{}
	RawValue     []byte
}

// Interpret a raw DataRecord into a list of InterpretedFields.
func (s *Session) Interpret(ds *DataRecord) []InterpretedField {
	tpl := s.templates[ds.TemplateId]
	if tpl == nil {
		return nil
	}

	fieldList := make([]InterpretedField, len(tpl))

	for i, field := range tpl {
		intf := InterpretedField{FieldId: field.FieldId, EnterpriseId: field.EnterpriseId}

		entry, ok := s.dictionary[dictionaryKey{field.EnterpriseId, field.FieldId}]
		if !ok {
			intf.RawValue = ds.Fields[i]
		} else {
			intf.Name = entry.Name
			intf.Value = interpretBytes(ds.Fields[i], entry.Type)
		}

		fieldList[i] = intf
	}

	return fieldList
}

// Add a DictionaryEntry (containing a vendor field) to the dictionary used by Interpret.
func (s *Session) AddDictionaryEntry(e DictionaryEntry) {
	s.dictionary[dictionaryKey{e.EnterpriseId, e.FieldId}] = e
}

func interpretBytes(bs []byte, t FieldType) interface{} {
	switch t {
	case Uint8, Uint16, Uint32, Uint64:
		var s uint64
		for _, b := range bs {
			s = s << 8
			s += uint64(b)
		}
		return s
	case Int8:
		return int8(bs[0])
	case Int16:
		var s int16
		binary.Read(bytes.NewBuffer(bs), binary.BigEndian, &s)
		return s
	case Int32:
		var s int32
		binary.Read(bytes.NewBuffer(bs), binary.BigEndian, &s)
		return s
	case Int64:
		var s int64
		binary.Read(bytes.NewBuffer(bs), binary.BigEndian, &s)
		return s
	case Float32:
		var s float32
		binary.Read(bytes.NewBuffer(bs), binary.BigEndian, &s)
		return s
	case Float64:
		var s float64
		binary.Read(bytes.NewBuffer(bs), binary.BigEndian, &s)
		return s
	case Boolean:
		return bs[0] != 0
	case MacAddress, OctetArray:
		return bs
	case String:
		return string(bs)
	case Ipv4Address:
		return fmt.Sprintf("%d.%d.%d.%d", bs[0], bs[1], bs[2], bs[3])
	case Ipv6Address:
		return fmt.Sprintf("%x:%x:%x:%x:%x:%x:%x:%x",
			int(bs[0])<<8+int(bs[1]),
			int(bs[2])<<8+int(bs[3]),
			int(bs[4])<<8+int(bs[5]),
			int(bs[5])<<8+int(bs[7]),
			int(bs[6])<<8+int(bs[9]),
			int(bs[10])<<8+int(bs[11]),
			int(bs[12])<<8+int(bs[13]),
			int(bs[14])<<8+int(bs[15]))
	}
	return bs
}
