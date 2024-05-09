// Copyright (c) 2024 Bryan Frimin <bryan@frimin.fr>.
//
// Permission to use, copy, modify, and/or distribute this software
// for any purpose with or without fee is hereby granted, provided
// that the above copyright notice and this permission notice appear
// in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
// WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
// AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR
// CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS
// OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
// NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

package uuid

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"
)

type (
	Version byte

	UUID [16]byte

	UUIDs []UUID
)

var (
	Nil UUID

	ErrInvalidFormat = errors.New("invalid format")
)

// String implements fmt.Stringer.
func (v Version) String() string {
	return fmt.Sprintf("%d", v)
}

// String implements fmt.Stringer.
func (uuids UUIDs) String() []string {
	var elements = make([]string, len(uuids))

	for i, uuid := range uuids {
		elements[i] = uuid.String()
	}

	return elements
}

func NewV4() (UUID, error) {
	var uuid UUID

	_, err := io.ReadFull(rand.Reader, uuid[:])
	if err != nil {
		return Nil, err
	}

	uuid[6] = uuid[6]&0x0F | 0x40
	uuid[8] = uuid[8]&0x3F | 0x80

	return uuid, nil
}

func NewV7() (UUID, error) {
	var uuid UUID

	timestamp := uint64(time.Now().UnixMilli())
	binary.BigEndian.PutUint64(uuid[:8], timestamp<<16)

	uuid[6] = uuid[6]&0x0F | 0x70

	if _, err := rand.Read(uuid[8:]); err != nil {
		return Nil, err
	}

	uuid[8] = uuid[8]&0x3F | 0x80

	return uuid, nil
}

// FromBytes creates a new UUID from a byte slice. Returns an error if
// the slice does not have a length of 16. The bytes are copied from
// the slice.
func FromBytes(b []byte) (UUID, error) {
	var uuid UUID

	err := uuid.UnmarshalBinary(b)

	return uuid, err
}

// Parse decodes s into a UUID or returns an error if it cannot be
// parsed.
func Parse(s string) (UUID, error) {
	return ParseBytes([]byte(s))
}

// ParseBytes is like Parse, except it parses a byte slice instead of
// a string.
func ParseBytes(b []byte) (UUID, error) {
	var uuid UUID

	if len(b) != 36 {
		return Nil, ErrInvalidFormat
	}

	if b[8] != '-' || b[13] != '-' || b[18] != '-' || b[23] != '-' {
		return uuid, ErrInvalidFormat
	}

	if _, err := hex.Decode(uuid[0:4], b[0:8]); err != nil {
		return Nil, ErrInvalidFormat
	}

	if _, err := hex.Decode(uuid[4:6], b[9:13]); err != nil {
		return Nil, ErrInvalidFormat
	}

	if _, err := hex.Decode(uuid[6:8], b[14:18]); err != nil {
		return Nil, ErrInvalidFormat
	}

	if _, err := hex.Decode(uuid[8:10], b[19:23]); err != nil {
		return Nil, ErrInvalidFormat
	}

	if _, err := hex.Decode(uuid[10:16], b[24:36]); err != nil {
		return Nil, ErrInvalidFormat
	}

	return uuid, nil
}

// Version returns the version of uuid.
func (uuid UUID) Version() Version {
	return Version(uuid[6] >> 4)
}

// MarshalBinary implements encoding.BinaryUnmarshaler.
func (uuid UUID) MarshalBinary() ([]byte, error) {
	return uuid[:], nil
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler.
func (uuid *UUID) UnmarshalBinary(data []byte) error {
	if len(data) != 16 {
		return ErrInvalidFormat
	}

	copy(uuid[:], data)
	return nil
}

// MarshalText implements encoding.TextUnmarshaler.
func (uuid UUID) MarshalText() ([]byte, error) {
	buf := make([]byte, 36)

	_ = hex.Encode(buf, uuid[:4])
	buf[8] = '-'
	_ = hex.Encode(buf[9:13], uuid[4:6])
	buf[13] = '-'
	_ = hex.Encode(buf[14:18], uuid[6:8])
	buf[18] = '-'
	_ = hex.Encode(buf[19:23], uuid[8:10])
	buf[23] = '-'
	_ = hex.Encode(buf[24:], uuid[10:])

	return buf, nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (uuid *UUID) UnmarshalText(data []byte) error {
	id, err := ParseBytes(data)
	if err != nil {
		return err
	}
	*uuid = id
	return nil
}

// String implements fmt.Stringer.
func (uuid UUID) String() string {
	buf, _ := uuid.MarshalText()
	return string(buf)
}

// Timestamp returns the timestamp extracted from a UUID v7.
func (uuid UUID) Timestamp() time.Time {
	var t time.Time

	switch uuid.Version() {
	case 7:
		timestamp := binary.BigEndian.Uint64(uuid[:8]) >> 16
		t = time.UnixMilli(int64(timestamp))
	}

	return t
}
