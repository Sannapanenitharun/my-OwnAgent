package otlp

import (
	"encoding/binary"
	"math"
)

// Protobuf wire types used by the OTLP subset we encode.
const (
	wireVarint  = 0
	wireFixed64 = 1
	wireBytes   = 2
)

func appendKey(b []byte, field, wire int) []byte {
	return appendUvarint(b, uint64(field<<3|wire))
}

func appendUvarint(b []byte, v uint64) []byte {
	for v >= 0x80 {
		b = append(b, byte(v)|0x80)
		v >>= 7
	}
	return append(b, byte(v))
}

func appendTagString(b []byte, field int, s string) []byte {
	if s == "" {
		return b
	}
	b = appendKey(b, field, wireBytes)
	b = appendUvarint(b, uint64(len(s)))
	return append(b, s...)
}

func appendTagBytes(b []byte, field int, p []byte) []byte {
	if len(p) == 0 {
		return b
	}
	b = appendKey(b, field, wireBytes)
	b = appendUvarint(b, uint64(len(p)))
	return append(b, p...)
}

func appendTagMessage(b []byte, field int, msg []byte) []byte {
	if len(msg) == 0 {
		return b
	}
	return appendTagBytes(b, field, msg)
}

func appendTagUvarint(b []byte, field int, v uint64) []byte {
	b = appendKey(b, field, wireVarint)
	return appendUvarint(b, v)
}

func appendTagBool(b []byte, field int, v bool) []byte {
	if !v {
		return appendTagUvarint(b, field, 0)
	}
	return appendTagUvarint(b, field, 1)
}

func appendTagFixed64(b []byte, field int, v uint64) []byte {
	b = appendKey(b, field, wireFixed64)
	var tmp [8]byte
	binary.LittleEndian.PutUint64(tmp[:], v)
	return append(b, tmp[:]...)
}

func appendTagDouble(b []byte, field int, v float64) []byte {
	return appendTagFixed64(b, field, math.Float64bits(v))
}

func appendTagSFixed64(b []byte, field int, v int64) []byte {
	return appendTagFixed64(b, field, uint64(v))
}
