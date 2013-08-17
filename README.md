# ipfix
--
    import "github.com/calmh/ipfix"

Package ipfix implements an IPFIX (RFC 5101) parser and interpreter.

[![Build
Status](https://drone.io/github.com/calmh/ipfix/status.png)](https://drone.io/github.com/calmh/ipfix/latest)

An input stream in the form of an io.Reader is read and chunked into messages.
Template management and the standard IPFIX types are implemented so a fully
parsed data set can be produced. Vendor fields can be added at runtime.


### Example

To read an IPFIX stream, create a Session around a Reader, then call ReadMessage
repeatedly.

    s := ipfix.NewSession(os.Stdin)
    i := ipfix.NewInterpreter(s)

    for {
    	// ReadMessage will block until a full message is available.
    	msg, err := s.ReadMessage()
    	if err != nil {
    		panic(err)
    	}

    	for _, record := range msg.DataRecords {
    		// record contains raw enterpriseId, fieldId => []byte information
    		fmt.Println(record)

    		fieldsMap := i.Interpret(&record)
    		// fieldsMap is a map[string]interface{}, with types
    		// resolved to their natural equivalents and field
    		// names resolved for standard fields.
    		fmt.Println(fieldsMap)
    	}
    }

To add a vendor field to the dictionary so that it will be resolved by
Interpret, create a DictionaryEntry and call AddDictionaryEntry.

    e := ipfix.DictionaryEntry{Name: "someVendorField", FieldId: 42, EnterpriseId: 123456, Type: ipfix.Int32}
    s.AddDictionaryEntry(e)


### License

The MIT license.

## Usage

```go
var ErrRead = errors.New("short read - malformed packet?")
```

```go
var ErrVersion = errors.New("incorrect version field in message header - out of sync?")
```
The version field in IPFIX messages should always have the value 10. If it does
not, you get this error. It's probably a sign of a bug in the parser or the
exporter and that we have lost synchronization with the data stream.
Reestablishing the session is the only way forward at this point.

#### type DataRecord

```go
type DataRecord struct {
	TemplateId uint16
	Fields     [][]byte
}
```

The DataRecord represents a single exported flow. The Fields each describe
different aspects of the flow (source and destination address, counters,
service, etc.).

#### type DictionaryEntry

```go
type DictionaryEntry struct {
	Name         string
	FieldId      uint16
	EnterpriseId uint32
	Type         FieldType
}
```

DictionaryEntry provied a mapping between an (Enterprise, Field) pair and a Name
and Type.

#### type FieldType

```go
type FieldType string
```

IPFIX type of an Information Element ("Field").

```go
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
```
The available field types as defined by RFC 5102.

#### type InterpretedField

```go
type InterpretedField struct {
	Name         string
	EnterpriseId uint32
	FieldId      uint16
	Value        interface{}
	RawValue     []byte
}
```

An InterpretedField is a field with the field name filled in and the value
converted to the appropriate type. If this is not possible (because the name and
type of the field is unknown at the time of interpretation), Name will be the
empty string, Value will be a nil interface and RawValue will contain the
original bytes.

#### type Interpreter

```go
type Interpreter struct {
}
```

Interpreter provides translation between the raw bytes of a DataRecord and the
actual values as specified by the corresponding template.

#### func  NewInterpreter

```go
func NewInterpreter(s *Session) *Interpreter
```
NewInterpreter craets a new Interpreter based on the specified Session.

#### func (*Interpreter) AddDictionaryEntry

```go
func (i *Interpreter) AddDictionaryEntry(e DictionaryEntry)
```
Add a DictionaryEntry (containing a vendor field) to the dictionary used by
Interpret.

#### func (*Interpreter) Interpret

```go
func (i *Interpreter) Interpret(ds *DataRecord) []InterpretedField
```
Interpret a raw DataRecord into a list of InterpretedFields.

#### type Message

```go
type Message struct {
	Header          MessageHeader
	DataRecords     []DataRecord
	TemplateRecords []TemplateRecord
}
```

A Message is the top level construct representing an IPFIX message. A well
formed message contains one or more sets of data or template information.

#### type MessageHeader

```go
type MessageHeader struct {
	Version        uint16 // Always 0x0a
	Length         uint16
	ExportTime     uint32 // Epoch seconds
	SequenceNumber uint32
	DomainId       uint32
}
```

The MessageHeader provides metadata for the entire Message. The sequence number
and domain ID can be used to gain knowledge of messages lost on an unreliable
transport such as UDP.

#### type Session

```go
type Session struct {
}
```

The Session is the context for IPFIX messages.

#### func  NewSession

```go
func NewSession(reader io.Reader) *Session
```
NewSession initializes a new Session based on the provided io.Reader.

#### func (*Session) ReadMessage

```go
func (s *Session) ReadMessage() (msg *Message, err error)
```
ReadMessage extracts and returns one message from the IPFIX stream. As long as
err is nil, further messages can be read from the stream. Errors are not
recoverable -- once an error has been returned, ReadMessage should not be called
again on the same session.

#### type TemplateFieldSpecifier

```go
type TemplateFieldSpecifier struct {
	EnterpriseId uint32
	FieldId      uint16
	Length       uint16
}
```

The TemplateFieldSpecifier describes the ID and size of the corresponding Fields
in a DataRecord.

#### type TemplateRecord

```go
type TemplateRecord struct {
	TemplateId      uint16
	FieldSpecifiers []TemplateFieldSpecifier
}
```

The TemplateRecord describes a data template, as used by DataRecords.
