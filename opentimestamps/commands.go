package opentimestamps

import (
	"crypto/sha256"
	"io"
	"os"
)

func CreateDetachedTimestampForFile(
	path string, cal *RemoteCalendar,
) (*DetachedTimestamp, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	hasher := sha256.New()
	if _, err := io.Copy(hasher, f); err != nil {
		return nil, err
	}
	digest := hasher.Sum([]byte{})
	ts, err := cal.Submit(digest)
	if err != nil {
		return nil, err
	}
	return NewDetachedTimestamp(*opSHA256, digest, ts)
}

func CreateDetachedTimestampForHash(digest string, cal *RemoteCalendar) (*DetachedTimestamp, error) {
	digest_bytearr := []byte(digest)
	ts, err := cal.Submit(digest_bytearr)
	if err != nil {
		return nil, err
	}
	return NewDetachedTimestamp(*opSHA256, digest_bytearr, ts)
}
