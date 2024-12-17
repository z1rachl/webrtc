package webrtc

// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

import (
	"bytes"
	"encoding/binary"
)

// H265Payloader payloads H265 packets
type H265Payloader struct {
	spsNalu, ppsNalu, vpsNalu []byte
}

const (
	stapaNALUType = 24
	fuaNALUType   = 28
	fubNALUType   = 29
	vpsNALUType   = 32
	spsNALUType   = 33
	ppsNALUType   = 34

	fuaHeaderSize       = 2
	stapaHeaderSize     = 1
	stapaNALULengthSize = 2

	naluTypeBitmask   = 0x1F
	naluRefIdcBitmask = 0x60
	fuStartBitmask    = 0x80
	fuEndBitmask      = 0x40

	outputStapAHeader = 0x78
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
		naluRefIdc := nalu[0] & naluRefIdcBitmask

		println(naluType)

		switch {
		case naluType == vpsNALUType:
			p.vpsNalu = nalu
			return
		case naluType == spsNALUType:
			p.spsNalu = nalu
			return
		case naluType == ppsNALUType:
			p.ppsNalu = nalu
			return
		case p.spsNalu != nil && p.ppsNalu != nil && p.vpsNalu != nil:
			// Pack current NALU with SPS and PPS as STAP-A
			vpsLen := make([]byte, 2)
			binary.BigEndian.PutUint16(vpsLen, uint16(len(p.vpsNalu)))

			spsLen := make([]byte, 2)
			binary.BigEndian.PutUint16(spsLen, uint16(len(p.spsNalu)))

			ppsLen := make([]byte, 2)
			binary.BigEndian.PutUint16(ppsLen, uint16(len(p.ppsNalu)))

			stapANalu := []byte{outputStapAHeader}
			stapANalu = append(stapANalu, vpsLen...)
			stapANalu = append(stapANalu, p.vpsNalu...)
			stapANalu = append(stapANalu, spsLen...)
			stapANalu = append(stapANalu, p.spsNalu...)
			stapANalu = append(stapANalu, ppsLen...)
			stapANalu = append(stapANalu, p.ppsNalu...)
			if len(stapANalu) <= int(mtu) {
				out := make([]byte, len(stapANalu))
				copy(out, stapANalu)
				payloads = append(payloads, out)
			}

			p.spsNalu = nil
			p.ppsNalu = nil
			p.vpsNalu = nil
		}

		out := make([]byte, len(nalu))
		copy(out, nalu)
		payloads = append(payloads, out)
		return

		// Single NALU
		if len(nalu) <= int(mtu) {
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

			// +---------------+
			// |0|1|2|3|4|5|6|7|
			// +-+-+-+-+-+-+-+-+
			// |F|NRI|  Type   |
			// +---------------+
			out[0] = fuaNALUType
			out[0] |= naluRefIdc

			// +---------------+
			// |0|1|2|3|4|5|6|7|
			// +-+-+-+-+-+-+-+-+
			// |S|E|R|  Type   |
			// +---------------+

			out[1] = naluType
			if naluRemaining == naluLength {
				// Set start bit
				out[1] |= 1 << 7
			} else if naluRemaining-currentFragmentSize == 0 {
				// Set end bit
				out[1] |= 1 << 6
			}

			copy(out[fuaHeaderSize:], nalu[naluIndex:naluIndex+currentFragmentSize])
			payloads = append(payloads, out)

			naluRemaining -= currentFragmentSize
			naluIndex += currentFragmentSize
		}
	})

	return payloads
}
