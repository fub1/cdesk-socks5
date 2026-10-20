package gateway

import (
	"encoding/binary"
	"fmt"
	"io"
)

const ossMaxFrame = 65507

// RustDesk frames use a little-endian length shifted by two bits; the low
// two bits encode header size minus one. UDP carries the protobuf without it.
func readOSSFrame(r io.Reader) ([]byte, error) {
	var h [4]byte
	if _, err := io.ReadFull(r, h[:1]); err != nil {
		return nil, err
	}
	size := int(h[0]&3) + 1
	if _, err := io.ReadFull(r, h[1:size]); err != nil {
		return nil, err
	}
	n := binary.LittleEndian.Uint32(h[:]) >> 2
	if n > ossMaxFrame {
		return nil, fmt.Errorf("RustDesk frame exceeds %d bytes", ossMaxFrame)
	}
	b := make([]byte, int(n))
	_, err := io.ReadFull(r, b)
	return b, err
}

func writeOSSFrame(w io.Writer, b []byte) error {
	if len(b) > ossMaxFrame {
		return fmt.Errorf("RustDesk frame too large")
	}
	size := 1
	for len(b) >= 1<<(8*size-2) {
		size++
	}
	var h [4]byte
	binary.LittleEndian.PutUint32(h[:], uint32(len(b))<<2|uint32(size-1))
	if err := writeOSSAll(w, h[:size]); err != nil {
		return err
	}
	return writeOSSAll(w, b)
}

func writeOSSAll(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}

type ossField struct {
	number int
	wire   int
	value  uint64
	data   []byte
}

// Only the small protobuf envelope is inspected. Unknown ordinary fields are
// preserved by forwarding the original bytes, without a generated proto runtime.
func ossFields(b []byte) ([]ossField, error) {
	var fields []ossField
	for len(b) > 0 {
		if len(fields) >= 256 {
			return nil, fmt.Errorf("too many protobuf fields")
		}
		tag, n := binary.Uvarint(b)
		if n <= 0 || tag>>3 == 0 || tag>>3 > (1<<29)-1 {
			return nil, fmt.Errorf("invalid protobuf tag")
		}
		b = b[n:]
		f := ossField{number: int(tag >> 3), wire: int(tag & 7)}
		switch f.wire {
		case 0:
			f.value, n = binary.Uvarint(b)
			if n <= 0 {
				return nil, fmt.Errorf("invalid protobuf varint")
			}
			b = b[n:]
		case 1, 5:
			n = 8
			if f.wire == 5 {
				n = 4
			}
			if len(b) < n {
				return nil, io.ErrUnexpectedEOF
			}
			b = b[n:]
		case 2:
			v, k := binary.Uvarint(b)
			if k <= 0 || v > uint64(len(b)-k) {
				return nil, fmt.Errorf("invalid protobuf length")
			}
			b = b[k:]
			f.data = b[:int(v)]
			b = b[int(v):]
		default:
			return nil, fmt.Errorf("unsupported protobuf wire type")
		}
		fields = append(fields, f)
	}
	return fields, nil
}

func ossMessage(b []byte) (int, []byte, error) {
	fields, err := ossFields(b)
	if err != nil {
		return 0, nil, err
	}
	number := 0
	var body []byte
	for _, f := range fields {
		if f.number >= 6 && f.number <= 35 && f.wire == 2 {
			number, body = f.number, f.data
		}
	}
	if number == 0 {
		return 0, nil, fmt.Errorf("missing RustDesk message")
	}
	return number, body, nil
}

func ossBytes(number int, b []byte) []byte {
	var h [20]byte
	n := binary.PutUvarint(h[:], uint64(number<<3|2))
	n += binary.PutUvarint(h[n:], uint64(len(b)))
	out := append([]byte(nil), h[:n]...)
	return append(out, b...)
}

func ossRegistration(b []byte) (string, error) {
	fields, err := ossFields(b)
	if err != nil {
		return "", err
	}
	var id, uuid, pk []byte
	for _, f := range fields {
		if f.wire == 2 {
			switch f.number {
			case 1:
				id = f.data
			case 2:
				uuid = f.data
			case 3:
				pk = f.data
			}
		}
	}
	if len(id) < 6 || len(id) > 128 || len(uuid) == 0 || len(pk) != 32 {
		return "", fmt.Errorf("invalid RustDesk registration")
	}
	return string(id), nil
}

func ossScalar(b []byte, number int) (uint64, error) {
	fields, err := ossFields(b)
	if err != nil {
		return 0, err
	}
	var value uint64
	for _, f := range fields {
		if f.number == number && f.wire == 0 {
			value = f.value
		}
	}
	return value, nil
}
