package ipfix

import (
	"encoding/binary"
	"math"
	"net"
)

// Interpreter provides translation between the raw bytes of a DataRecord
// and the actual values as specified by the corresponding template.
type Interpreter struct {
	dictionary fieldDictionary
	session    *Session
}

// IPFIX type of an Information Element ("Field").
type FieldType int

// The available field types as defined by RFC 5102.
const (
	Uint8 FieldType = iota
	Uint16
	Uint32
	Uint64
	Int8
	Int16
	Int32
	Int64
	Float32
	Float64
	Boolean
	MacAddress
	OctetArray
	String
	DateTimeSeconds
	DateTimeMilliseconds
	DateTimeMicroseconds
	DateTimeNanoseconds
	Ipv4Address
	Ipv6Address
)

var FieldTypes = map[string]FieldType{
	"unsigned8":            Uint8,
	"unsigned16":           Uint16,
	"unsigned32":           Uint32,
	"unsigned64":           Uint64,
	"signed8":              Int8,
	"signed16":             Int16,
	"signed32":             Int32,
	"signed64":             Int64,
	"float32":              Float32,
	"float64":              Float64,
	"boolean":              Boolean,
	"macAddress":           MacAddress,
	"octetArray":           OctetArray,
	"string":               String,
	"dateTimeSeconds":      DateTimeSeconds,
	"dateTimeMilliseconds": DateTimeMilliseconds,
	"dateTimeMicroseconds": DateTimeMicroseconds,
	"dateTimeNanoseconds":  DateTimeNanoseconds,
	"ipv4Address":          Ipv4Address,
	"ipv6Address":          Ipv6Address,
}

// DictionaryEntry provied a mapping between an (Enterprise, Field) pair and a Name and Type.
type DictionaryEntry struct {
	Name         string
	FieldID      uint16
	EnterpriseID uint32
	Type         FieldType
}

func (f *FieldType) UnmarshalText(bs []byte) error {
	*f = FieldTypes[string(bs)]
	return nil
}

type dictionaryKey struct {
	EnterpriseID uint32
	FieldID      uint16
}

type fieldDictionary map[dictionaryKey]DictionaryEntry

// An InterpretedField is a field with the field name filled in and the value
// converted to the appropriate type.  If this is not possible (because the
// name and type of the field is unknown at the time of interpretation), Name
// will be the empty string, Value will be a nil interface and RawValue will
// contain the original bytes.
type InterpretedField struct {
	Name         string
	EnterpriseID uint32
	FieldID      uint16
	Value        interface{}
	RawValue     []byte
}

// NewInterpreter craets a new Interpreter based on the specified Session.
func NewInterpreter(s *Session) *Interpreter {
	return &Interpreter{builtinDictionary, s}
}

const reversePen = 29305

// Interpret a raw DataRecord into a list of InterpretedFields.
func (i *Interpreter) Interpret(rec DataRecord) []InterpretedField {
	tpl := i.session.templates[rec.TemplateID]
	if tpl == nil {
		return nil
	}
	fieldList := make([]InterpretedField, len(tpl))

	for j, field := range tpl {
		fieldList[j].FieldID = field.FieldID
		fieldList[j].EnterpriseID = field.EnterpriseID

		reverse := false
		enterpriseID := field.EnterpriseID

		if enterpriseID == reversePen {
			enterpriseID = 0
			reverse = true
		}

		if entry, ok := i.dictionary[dictionaryKey{enterpriseID, field.FieldID}]; ok {
			if reverse {
				fieldList[j].Name = entry.Name + "Reverse"
			} else {
				fieldList[j].Name = entry.Name
			}
			fieldList[j].Value = interpretBytes(rec.Fields[j], entry.Type)
		} else {
			fieldList[j].RawValue = rec.Fields[j]
		}
	}

	return fieldList
}

// InterpretInto interprets a raw DataRecord into an existing slice of
// InterpretedFields. If the slice is not long enouhg it will be reallocated.
func (i *Interpreter) InterpretInto(rec DataRecord, fieldList []InterpretedField) []InterpretedField {
	tpl := i.session.templates[rec.TemplateID]
	if tpl == nil {
		return nil
	}
	if len(fieldList) < len(tpl) {
		fieldList = make([]InterpretedField, len(tpl))
	} else {
		fieldList = fieldList[:len(tpl)]
	}

	for j, field := range tpl {
		fieldList[j].FieldID = field.FieldID
		fieldList[j].EnterpriseID = field.EnterpriseID

		if entry, ok := i.dictionary[dictionaryKey{field.EnterpriseID, field.FieldID}]; ok {
			fieldList[j].Name = entry.Name
			fieldList[j].Value = interpretBytes(rec.Fields[j], entry.Type)
		} else {
			fieldList[j].RawValue = rec.Fields[j]
		}
	}

	return fieldList
}

// AddDictionaryEntry adds a DictionaryEntry (containing a vendor field) to
// the dictionary used by Interpret.
func (i *Interpreter) AddDictionaryEntry(e DictionaryEntry) {
	i.dictionary[dictionaryKey{e.EnterpriseID, e.FieldID}] = e
}

func interpretBytes(bs []byte, t FieldType) interface{} {
	switch t {
	case Uint8:
		return bs[0]
	case Uint16:
		return binary.BigEndian.Uint16(bs)
	case Uint32, DateTimeSeconds:
		return binary.BigEndian.Uint32(bs)
	case Uint64:
		return binary.BigEndian.Uint64(bs)
	case Int8:
		return int8(bs[0])
	case Int16:
		return int16(binary.BigEndian.Uint16(bs))
	case Int32:
		return int32(binary.BigEndian.Uint32(bs))
	case Int64:
		return int64(binary.BigEndian.Uint64(bs))
	case Float32:
		return math.Float32frombits(binary.BigEndian.Uint32(bs))
	case Float64:
		return math.Float64frombits(binary.BigEndian.Uint64(bs))
	case Boolean:
		return bs[0] != 0
	case MacAddress, OctetArray:
		return bs
	case String:
		return string(bs)
	case Ipv4Address, Ipv6Address:
		return net.IP(bs)
	}
	return bs
}
