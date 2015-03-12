package ipfix

import "testing"

func TestRFC5103(t *testing.T) {
	f := builtinDictionary[dictionaryKey{0, 239}]
	if f.Name != "biflowDirection" {
		t.Errorf("Incorrect name for biflowDirection in %+v", f)
	}
	if f.FieldID != 239 {
		t.Errorf("Incorrect field ID in %+v", f)
	}

	f = builtinDictionary[dictionaryKey{29305, 85}]
	if f.Name != "reverseOctetTotalCount" {
		t.Errorf("Incorrect name for reverseOctetTotalCount in %+v", f)
	}
	if f.FieldID != 85 {
		t.Errorf("Incorrect field ID in %+v", f)
	}
	if f.EnterpriseID != 29305 {
		t.Errorf("Incorrect reverse PEN in %+v", f)
	}

	_, ok := builtinDictionary[dictionaryKey{29305, 173}]
	if ok {
		t.Errorf("Incorrect existence of non-reversible flowKeyIndicator")
	}
}
