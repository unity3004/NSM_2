package util

import (
	"encoding/base64"
	"errors"
	"strings"
	"time"
)

// ErrInvalidCursor is returned for a cursor that doesn't decode to the
// expected shape — most likely a client hand-editing a query string rather
// than passing back what a previous response gave it.
var ErrInvalidCursor = errors.New("invalid pagination cursor")

// EncodeCursor packs the sort key of the last row on a page (created_at,
// id) into the opaque string list endpoints return as page.next_cursor.
// Base64 (not a raw string) so the wire format never accidentally implies
// clients may construct or parse one themselves.
func EncodeCursor(createdAt time.Time, id string) string {
	raw := createdAt.UTC().Format(time.RFC3339Nano) + "|" + id
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

// DecodeCursor reverses EncodeCursor.
func DecodeCursor(cursor string) (createdAt time.Time, id string, err error) {
	raw, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return time.Time{}, "", ErrInvalidCursor
	}
	parts := strings.SplitN(string(raw), "|", 2)
	if len(parts) != 2 {
		return time.Time{}, "", ErrInvalidCursor
	}
	t, err := time.Parse(time.RFC3339Nano, parts[0])
	if err != nil {
		return time.Time{}, "", ErrInvalidCursor
	}
	return t, parts[1], nil
}
