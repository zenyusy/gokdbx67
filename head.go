package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
)

const (
	SigLen    = 8
	VerLen    = 4
	GoodSig   = "\x03\xD9\xA2\x9A\x67\xFB\x4B\xB5"
	GoodAES   = "\x31\xC1\xF2\xE6\xBF\x71\x43\x50\xBE\x58\x05\x21\x6A\xFC\x5A\xFF"
	GoodSalsa = "\x02\x00\x00\x00"
	MetaLen   = 3
)

type header struct {
	keyAES     []byte
	seed       []byte
	iv         []byte
	mac        []byte
	keySalsa   []byte
	compressed bool
	rounds     uint64
}

func getHead(fp *os.File) (*header, error) {
	sig := make([]byte, SigLen)

	if n, serr := fp.Read(sig); serr != nil {
		return nil, fmt.Errorf("read header sig: %v", serr)
	} else if n != SigLen {
		return nil, fmt.Errorf("sig len expect %d got %d", SigLen, n)
	} else if string(sig) != GoodSig {
		return nil, errors.New("header unsupported")
	}

	ver := make([]byte, VerLen)
	if n, verr := fp.Read(ver); verr != nil {
		return nil, fmt.Errorf("read header ver: %v", verr)
	} else if n != VerLen {
		return nil, fmt.Errorf("ver len expect %d got %d", VerLen, n)
	}

	return parseHeadItem(fp)
}

func parseHeadItem(fp *os.File) (*header, error) {
	var ret header
	meta := make([]byte, MetaLen) // Key uint8 + Len uint16

	for i := 99; i != 0; i-- {
		if n, berr := fp.Read(meta); berr != nil {
			return nil, fmt.Errorf("read header item: %v", berr)
		} else if n != MetaLen {
			return nil, fmt.Errorf("header meta len expect %d got %d", MetaLen, n)
		}
		size := int(meta[1]) | int(meta[2])<<8
		if meta[0] == 0 {
			// read off
			if _, serr := fp.Seek(int64(size), 1); serr != nil {
				return nil, fmt.Errorf("seek: %v", serr)
			}
			return &ret, nil
		}

		data := make([]byte, size)
		if n, derr := fp.Read(data); derr != nil {
			return nil, fmt.Errorf("read header[%d]: %v", meta[0], derr)
		} else if n != size {
			return nil, fmt.Errorf("header[%d] len expect %d got %d", meta[0], size, n)
		}

		switch meta[0] {
		case 2:
			if string(data) != GoodAES {
				return nil, errors.New("cipher not AES")
			}
		case 10:
			if string(data) != GoodSalsa {
				return nil, errors.New("stream cipher not Salsa20")
			}
		case 6:
			if size == 8 {
				ret.rounds = binary.LittleEndian.Uint64(data)
			} else {
				return nil, errors.New("header bad 'rounds'")
			}
		case 5:
			if size == 32 || size == 24 || size == 16 {
				ret.keyAES = data
			} else {
				return nil, errors.New("header bad AES key")
			}
		case 4:
			ret.seed = data
		case 7:
			if size == 16 {
				ret.iv = data
			} else {
				return nil, errors.New("header bad AES IV")
			}
		case 9:
			ret.mac = data
		case 3:
			if size == 4 {
				ret.compressed = data[0] != 0 || data[1] != 0 || data[2] != 0 || data[3] != 0
			} else {
				return nil, errors.New("header bad 'compressed'")
			}
		case 8:
			ret.keySalsa = data
		}
	}
	return nil, errors.New("bad header")
}
