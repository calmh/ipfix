package ipfix_test

import (
	"fmt"
	"os"

	"github.com/calmh/ipfix"
)

func ExampleSession() {
	s := ipfix.NewSession()

	for {
		// ParseReader will block until a full message is available.
		msg, err := s.ParseReader(os.Stdin)
		if err != nil {
			panic(err)
		}

		for _, record := range msg.DataRecords {
			// record contains raw enterpriseId, fieldId => []byte information
			fmt.Println(record)
		}
	}
}

func ExampleInterpreter() {
	s := ipfix.NewSession()
	i := ipfix.NewInterpreter(s)

	for {
		// ParseReader will block until a full message is available.
		msg, err := s.ParseReader(os.Stdin)
		if err != nil {
			panic(err)
		}

		var fieldList []ipfix.InterpretedField
		for _, record := range msg.DataRecords {
			fieldList = i.InterpretInto(record, fieldList)
			fmt.Println(fieldList)
		}
	}
}

func ExampleInterpreter_AddDictionaryEntry() {
	s := ipfix.NewSession()
	i := ipfix.NewInterpreter(s)

	entry := ipfix.DictionaryEntry{
		Name:         "someVendorField",
		FieldID:      42,
		EnterpriseID: 123456,
		Type:         ipfix.Int32,
	}

	i.AddDictionaryEntry(entry)

	// Now use i.Interpret() etc as usual.
}
