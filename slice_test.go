package ipfix

import (
	"bytes"
	"testing"
)

func TestSliceCut(t *testing.T) {
	s := newSlice([]byte{1, 2, 3, 4, 5, 6, 7, 8})
	r := s.Cut(4)

	if !bytes.Equal(r, []byte{1, 2, 3, 4}) {
		t.Errorf("%v != [1 2 3 4]", r)
	}

	if !bytes.Equal(s.bytes(), []byte{5, 6, 7, 8}) {
		t.Errorf("%v != [5 6 7 8]", s)
	}
}

func TestSliceUint16(t *testing.T) {
	s := newSlice([]byte{1, 2, 3, 4, 5})

	if v := s.Uint16(); v != 1<<8+2 {
		t.Errorf("%v != 1<<8+2", v)
	}

	if v := s.Uint16(); v != 3<<8+4 {
		t.Errorf("%v != 3<<4+2", v)
	}

	if err := s.Error(); err != nil {
		t.Error("unexpected", err)
	}

	if v := s.Uint16(); v != 0 {
		t.Errorf("%v != 0", v)
	}

	if err := s.Error(); err == nil {
		t.Error("unexpected nil error")
	}

	if v := s.Len(); v != 1 {
		t.Errorf("len %d != 1", v)
	}
}
