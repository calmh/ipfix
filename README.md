ipfix
=====

Package ipfix implements an IPFIX (RFC 5101) parser and interpreter.

An input stream in the form of an io.Reader is read and chunked into
messages. Template management and the standard IPFIX types are
implemented so a fully parsed data set can be produced. Vendor fields
can be added at runtime.

To read an IPFIX stream, create a Session around a Reader, then call
ReadMessage repeatedly.

```go
s := ipfix.NewSession(os.Stdin)

for {
    // ReadMessage will block until a full message is available.
    msg, err := s.ReadMessage()
    if err != nil {
        panic(err)
    }

    for _, ds := range msg.DataSets {
        // ds contains raw enterpriseId, fieldId => []byte information
        fmt.Println(ds)

        // fieldsMap is a map[string]interface{}, with types
        // resolved to their natural equivalents and field
        // names resolved for standard fields.
        fieldsMap := s.Interpret(&ds)
        fmt.Println(fieldsMap)
    }
}
```

To add a vendor field to the dictionary so that it will be resolved by
Interpret, create a DictionaryEntry and call AddDictionaryEntry.

```go
e := ipfix.DictionaryEntry{Name: "someVendorField", FieldId: 42, EnterpriseId: 123456, Type: ipfix.Int32}
s.AddDictionaryEntry(e)
```
Installation
------------

    $ go get github.com/calmh/ipfix

API Docs
--------

http://godoc.org/github.com/calmh/ipfix

License
-------

MIT

