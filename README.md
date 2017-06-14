ipfix
-----

Package ipfix implements an IPFIX (RFC 5101) parser and interpreter.

[![Build & Test](https://img.shields.io/teamcity/https/build.kastelo.net/s/Ipfix_Test.svg?style=flat-square&label=build+%26+tests)](https://build.kastelo.net/project.html?projectId=Ipfix&tab=projectOverview)
[![API Documentation](http://img.shields.io/badge/api-Godoc-blue.svg?style=flat-square)](http://godoc.org/github.com/calmh/ipfix)
[![MIT License](http://img.shields.io/badge/license-MIT-blue.svg?style=flat-square)](http://opensource.org/licenses/MIT)

Input data from an `io.Reader` or a `[]byte` is parsed and chunked into
messages. Template management and the standard IPFIX types are implemented
so a fully parsed data set can be produced. Vendor fields can be added at
runtime.

## Example

To read an IPFIX stream, create a Session and then use ParseBuffer to parse
data coming from a single UDP packet or similar.

```go
var conn net.PacketConn // from somewhere
buf := make([]byte, 65507) // maximum UDP payload length
s := ipfix.NewSession()
for {
    n, _, err := conn.ReadFrom(buf)
    // handle err
    msg, err := s.ParseBuffer(buf[:n])
    // handle msg and err
}
```

To interpret records for correct data types and field names, use an interpreter:

```go
i := ipfix.NewInterpreter(s)
var fieldList []ipfix.InterpretedField
for _, rec := range msg.DataRecords {
    fieldList = i.InterpretInto(rec, fieldList[:cap(fieldList)])
    // handle the field list
}
```

To add a vendor field to the dictionary so that it will be resolved by
Interpret, create a DictionaryEntry and call AddDictionaryEntry.

```go
e := ipfix.DictionaryEntry{
    Name: "someVendorField",
    FieldId: 42,
    EnterpriseId: 123456,
    Type: ipfix.Int32
}
i.AddDictionaryEntry(e)
```

## License

The MIT license.

## Usage

See the [documentation](http://godoc.org/github.com/calmh/ipfix).

