package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"errors"
	"io"
)

const (
	CheckLen = 32
	SizeLen  = 4
)

func bodyToXMLReader(body []byte, compressed bool) (io.Reader, error) {
	idx := 0
	dest := 0
	length := len(body)

	for i := 9999; i != 0; i-- {
		// 4B drop, 32B checksum, 4B size, `size`B data
		idx += 4
		if idx >= length {
			break
		}

		// [idx, checkEnd) check
		checkEnd := idx + CheckLen
		if checkEnd >= length {
			return nil, errors.New("2XML read check overflow")
		}

		// [checkEnd, sizeEnd) size
		sizeEnd := checkEnd + SizeLen
		if sizeEnd >= length {
			return nil, errors.New("2XML read size overflow")
		}

		// all zero = normal exit
		allZero := true
		for j := idx; j < sizeEnd; j++ {
			if body[j] != 0 {
				allZero = false
				break
			}
		}
		if allZero {
			if compressed {
				return gzip.NewReader(bytes.NewReader(body[:dest:dest]))
			}
			return bytes.NewReader(body[:dest:dest]), nil
		}

		// little endian int32
		size := int(body[checkEnd])
		checkEnd++
		for shift := 8; checkEnd != sizeEnd; shift += 8 {
			size |= int(body[checkEnd]) << shift
			checkEnd++
		}

		// [sizeEnd, dataEnd) data
		dataEnd := sizeEnd + size
		if dataEnd >= length {
			break
		}
		// compare []byte [32]byte
		for _, expect := range sha256.Sum256(body[sizeEnd:dataEnd]) {
			if body[idx] != expect {
				return nil, errors.New("2XML body corrupted")
			}
			idx++
		}

		// reuse `body` to hold data
		// faster than `dest : bytes.Buffer .Write(data)`
		copy(body[dest:], body[sizeEnd:dataEnd])
		dest += size
		idx = dataEnd
	}

	return nil, errors.New("2XML internal error")
}
