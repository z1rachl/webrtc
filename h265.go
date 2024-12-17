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

	fuaHeaderSize       = 3
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

		fmt.Printf("OUT naluType: %d", naluType)

		if naluType == vpsNALUType || naluType == spsNALUType || naluType == ppsNALUType {
			fmt.Printf("OUT naluType: %d/%d; set=%v\n", naluType, naluType, nalu[:8])

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

		// FU-A
		maxFragmentSize := int(mtu) - fuaHeaderSize

		// The FU payload consists of fragments of the payload of the fragmented
		// NAL unit so that if the fragmentation unit payloads of consecutive
		// FUs are sequentially concatenated, the payload of the fragmented NAL
		// unit can be reconstructed.  The NAL unit type octet of the fragmented
		// NAL unit is not included as such in the fragmentation unit payload,
		// 	but rather the information of the NAL unit type octet of the
		// fragmented NAL unit is conveyed in the F and NRI fields of the FU
		// indicator octet of the fragmentation unit and in the type field of
		// the FU header.  An FU payload MAY have any number of octets and MAY
		// be empty.

		// According to the RFC, the first octet is skipped due to redundant information
		naluIndex := 1
		naluLength := len(nalu) - naluIndex
		naluRemaining := naluLength

		if min(maxFragmentSize, naluRemaining) <= 0 {
			return
		}

		for naluRemaining > 0 {
			currentFragmentSize := min(maxFragmentSize, naluRemaining)
			out := make([]byte, fuaHeaderSize+currentFragmentSize)

			out[0] = 98
			out[1] = nalu[1]
			out[2] = naluType

			if naluRemaining == naluLength {
				out[2] |= 1 << 7
			} else if naluRemaining-currentFragmentSize == 0 {
				out[2] |= 1 << 6
			}

			copy(out[fuaHeaderSize:], nalu[naluIndex:naluIndex+currentFragmentSize])

			fmt.Printf("OUT naluType: %d/%d; set=%v\n", fuaNALUType, naluType, out[:8])

			payloads = append(payloads, out)

			naluRemaining -= currentFragmentSize
			naluIndex += currentFragmentSize
		}
	})

	return payloads
}
