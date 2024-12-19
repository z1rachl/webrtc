package webrtc

// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

import (
	"bytes"
	"fmt"
)

// H265Payloader payloads H265 packets
type H265Payloader struct {
	spsNalu, ppsNalu, vpsNalu []byte
}

const (
	fuaNALUType = 49
	vpsNALUType = 32
	spsNALUType = 33
	ppsNALUType = 34

	fuaHeaderSize       = 2
	stapaHeaderSize     = 1
	stapaNALULengthSize = 2
)

// nolint:gochecknoglobals
var (
	naluStartCode       = []byte{0x00, 0x00, 0x01}
	annexbNALUStartCode = []byte{0x00, 0x00, 0x00, 0x01}
)

func emitNalus(nals []byte, emit func([]byte)) {
	start := 0
	length := len(nals)

	for start < length {
		end := bytes.Index(nals[start:], annexbNALUStartCode)
		offset := 4
		if end == -1 {
			end = bytes.Index(nals[start:], naluStartCode)
			offset = 3
		}
		if end == -1 {
			emit(nals[start:])
			break
		}

		emit(nals[start : start+end])

		// next NAL start position
		start += end + offset
	}
}

// Payload fragments a H264 packet across one or more byte arrays
func (p *H265Payloader) Payload(mtu uint16, payload []byte) [][]byte {
	var payloads [][]byte
	if len(payload) == 0 {
		return payloads
	}

	emitNalus(payload, func(nalu []byte) {
		if len(nalu) == 0 {
			return
		}

		naluType := (nalu[0] >> 1) & 0x3f

		if naluType == vpsNALUType || naluType == spsNALUType || naluType == ppsNALUType {
			payloads = append(payloads, nalu)
			return
		}

		// Single NALU
		if len(nalu) <= int(mtu) {
			fmt.Printf("OUT naluType: %d/%d; set=%v\n", naluType, naluType, nalu[:8])

			out := make([]byte, len(nalu))
			copy(out, nalu)
			payloads = append(payloads, out)
			return
		}

		maxFragmentSize := int(mtu) - fuaHeaderSize

		naluIndex := 2
		naluLength := len(nalu) - naluIndex
		naluRemaining := naluLength

		if min(maxFragmentSize, naluRemaining) <= 0 {
			return
		}

		for naluRemaining > 0 {
			currentFragmentSize := min(maxFragmentSize, naluRemaining)
			out := make([]byte, fuaHeaderSize+currentFragmentSize)

			out[0] = (49 << 1) | (nalu[0]<<7)>>7
			out[1] = naluType

			if naluRemaining == naluLength {
				out[1] |= 1 << 7
			} else if naluRemaining-currentFragmentSize == 0 {
				out[1] |= 1 << 6
			}

			copy(out[fuaHeaderSize:], nalu[naluIndex:naluIndex+currentFragmentSize])

			payloads = append(payloads, out)

			naluRemaining -= currentFragmentSize
			naluIndex += currentFragmentSize
		}
	})

	for _, p := range payloads {
		fmt.Printf("OUT nal=%v\n", p[:16])
	}

	return payloads
}
