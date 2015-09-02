// +build gofuzz

package ipfix

import (
	"bytes"
	"io"
)

func Fuzz(bs []byte) int {
	p := NewSession()
	r := bytes.NewReader(bs)

	_, err := p.ParseReader(r)
	for err == nil {
		_, err = p.ParseReader(r)
	}
	if err == io.EOF {
		return 1
	}

	return 0
}
