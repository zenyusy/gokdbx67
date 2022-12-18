package main

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
)

type SalsaStream struct {
	state []uint32
	block []byte
}

func NewSalsaStream(key []byte) *SalsaStream {
	state := []uint32{
		//"expa"    k k k
		0x61707865, 0, 0, 0,
		//k "nd 3" nonce nonce
		0, 0x3320646e, 1258893544, 710746263,
		//pos pos "2-by" k
		0, 0, 0x79622d32, 0,
		//k k k "te k"
		0, 0, 0, 0x6b206574}

	k := 1 // fill eight `k` 1,2,3,4,11,12,13,14

	for i, v := range sha256.Sum256(key) {
		switch i & 3 {
		case 0:
			state[k] = uint32(v)
		case 1:
			state[k] |= uint32(v) << 8
		case 2:
			state[k] |= uint32(v) << 16
		case 3:
			state[k] |= uint32(v) << 24
			if k == 4 {
				k = 11
			} else {
				k++
			}
		}
	}

	return &SalsaStream{state: state}
}

func (s *SalsaStream) Unpack(payload string) ([]byte, error) {
	if len(payload) == 0 {
		return nil, nil
	}

	data, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return nil, fmt.Errorf("salsa b64decode: %v", err)
	}

	dataLen := len(data)
	dataI := 0
	blockLen := len(s.block)

	// enough
	if blockLen >= dataLen {
		useI := 0
		for ; dataI != dataLen; dataI++ {
			data[dataI] ^= s.block[useI]
			useI++
		}
		s.block = s.block[useI:]
		return data, nil
	}

	// not enough, do part of data first
	for useI := 0; useI != blockLen; useI++ {
		data[dataI] ^= s.block[useI]
		dataI++
	}

	return data, s.handle(data, dataI)
}

func (s *SalsaStream) handle(data []byte, dataI int) error {
	dataLen := len(data)
	x := make([]uint32, 16)
	for t := 0xf3f3f3; t != 0; t-- {
		copy(x, s.state)
		for i := 0; i < 10; i++ {
			x[4] ^= rotl32(x[0]+x[12], 7)
			x[8] ^= rotl32(x[4]+x[0], 9)
			x[12] ^= rotl32(x[8]+x[4], 13)
			x[0] ^= rotl32(x[12]+x[8], 18)
			x[9] ^= rotl32(x[5]+x[1], 7)
			x[13] ^= rotl32(x[9]+x[5], 9)
			x[1] ^= rotl32(x[13]+x[9], 13)
			x[5] ^= rotl32(x[1]+x[13], 18)
			x[14] ^= rotl32(x[10]+x[6], 7)
			x[2] ^= rotl32(x[14]+x[10], 9)
			x[6] ^= rotl32(x[2]+x[14], 13)
			x[10] ^= rotl32(x[6]+x[2], 18)
			x[3] ^= rotl32(x[15]+x[11], 7)
			x[7] ^= rotl32(x[3]+x[15], 9)
			x[11] ^= rotl32(x[7]+x[3], 13)
			x[15] ^= rotl32(x[11]+x[7], 18)
			x[1] ^= rotl32(x[0]+x[3], 7)
			x[2] ^= rotl32(x[1]+x[0], 9)
			x[3] ^= rotl32(x[2]+x[1], 13)
			x[0] ^= rotl32(x[3]+x[2], 18)
			x[6] ^= rotl32(x[5]+x[4], 7)
			x[7] ^= rotl32(x[6]+x[5], 9)
			x[4] ^= rotl32(x[7]+x[6], 13)
			x[5] ^= rotl32(x[4]+x[7], 18)
			x[11] ^= rotl32(x[10]+x[9], 7)
			x[8] ^= rotl32(x[11]+x[10], 9)
			x[9] ^= rotl32(x[8]+x[11], 13)
			x[10] ^= rotl32(x[9]+x[8], 18)
			x[12] ^= rotl32(x[15]+x[14], 7)
			x[13] ^= rotl32(x[12]+x[15], 9)
			x[14] ^= rotl32(x[13]+x[12], 13)
			x[15] ^= rotl32(x[14]+x[13], 18)
		}

		if dataLen >= 64+dataI {
			// generate 64B, all for data, no leftover
			for i, v := range x {
				v += s.state[i]
				data[dataI] ^= byte(v)
				dataI++
				v >>= 8
				data[dataI] ^= byte(v)
				dataI++
				v >>= 8
				data[dataI] ^= byte(v)
				dataI++
				v >>= 8
				data[dataI] ^= byte(v)
				dataI++
			}
		} else {
			// data done, leftover
			blk := make([]byte, 64+dataI-dataLen)
			blkI := 0
			forData := true
			for i, v := range x {
				v += s.state[i]
				for j := 0; j < 4; j++ {
					if forData {
						data[dataI] ^= byte(v)
						dataI++
						if dataI == dataLen {
							forData = false
						}
					} else {
						blk[blkI] = byte(v)
						blkI++
					}
					v >>= 8
				}
			}
			s.block = blk
		}

		s.state[8]++
		if s.state[8] == 0 {
			s.state[9]++
		}
		if dataI >= dataLen {
			return nil
		}
	}
	return errors.New("salsa internal error")
}

func rotl32(x uint32, b uint) uint32 {
	return (x << b) | (x >> (32 - b))
}
