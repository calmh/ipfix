/*
Package ipfix implements an IPFIX (RFC 5101) parser and interpreter.

[![Build Status](https://drone.io/github.com/calmh/ipfix/status.png)](https://drone.io/github.com/calmh/ipfix/latest)

An input stream in the form of an io.Reader is read and chunked into
messages. Template management and the standard IPFIX types are
implemented so a fully parsed data set can be produced. Vendor fields
can be added at runtime.

Example

To read an IPFIX stream, create a Session around a Reader, then call
ReadMessage repeatedly.

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

License

The MIT license.

*/
package ipfix

