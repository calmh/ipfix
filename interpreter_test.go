package ipfix

import (
	"testing"
)

func TestInterpretUint(t *testing.T) {
	bs := []byte{0xf7, 2, 3, 4, 5, 6, 7, 8}
	v := interpretBytes(bs, Uint64)
	if v != uint64(0xf702030405060708) {
		t.Errorf("%d != %d", v, 0x0102030405060708)
	}

	bs = []byte{0xf7, 2, 3, 4}
	v = interpretBytes(bs, Uint32)
	if v != uint64(0xf7020304) {
		t.Errorf("%d != %d", v, 0x01020304)
	}

	bs = []byte{0xf7, 4}
	v = interpretBytes(bs, Uint16)
	if v != uint64(0xf704) {
		t.Errorf("%d != %d", v, 0x0104)
	}

	bs = []byte{0xf7}
	v = interpretBytes(bs, Uint8)
	if v != uint64(0xf7) {
		t.Errorf("%d != %d", v, 0xf7)
	}
}

func TestInterpretInt(t *testing.T) {
	bs := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	v := interpretBytes(bs, Int64)
	if v != int64(0x0102030405060708) {
		t.Errorf("%d != %d", v, 0x0102030405060708)
	}

	bs = []byte{1, 2, 3, 4}
	v = interpretBytes(bs, Int32)
	if v != int32(0x01020304) {
		t.Errorf("%d != %d", v, 0x01020304)
	}

	bs = []byte{1, 4}
	v = interpretBytes(bs, Int16)
	if v != int16(0x0104) {
		t.Errorf("%d != %d", v, 0x0104)
	}

	bs = []byte{14}
	v = interpretBytes(bs, Int8)
	if v != int8(14) {
		t.Errorf("%d != %d", v, 14)
	}
}

func TestInterpretBool(t *testing.T) {
	bs := []byte{8}
	v := interpretBytes(bs, Boolean)
	if v != true {
		t.Errorf("%d != %d", v, true)
	}

	bs = []byte{0}
	v = interpretBytes(bs, Boolean)
	if v != false {
		t.Errorf("%d != %d", v, true)
	}
}

func TestInterpretString(t *testing.T) {
	bs := []byte{0x48, 0x61, 0x6c, 0x6c, 0xc3, 0xa5, 0x0a}
	v := interpretBytes(bs, String)
	if v != "Hallå\n" {
		t.Errorf("%d != %d", v, "Hallå\n")
	}
}

func TestInterpretIpv4(t *testing.T) {
	bs := []byte{172, 16, 32, 42}
	v := interpretBytes(bs, Ipv4Address)
	if v != "172.16.32.42" {
		t.Errorf("%d != %d", v, "172.16.32.42")
	}
}
