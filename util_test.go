package cryptopals

import (
	"bytes"
	"testing"
)

func TestPopCount(t *testing.T) {
	// TODO: write a test for me?
}

func TestHammingDistance(t *testing.T) {
	dist := HammingDistance([]byte("this is a test"), []byte("wokka wokka!!!"))
	if dist != 37 {
		t.Errorf("TestHammingDistance: Unexpected result: %d", dist)
	}
}

func TestSplitBytes(t *testing.T) {
	chunks := SplitBytes([]byte{1, 2, 3, 4, 5, 6, 7}, 3)
	if !bytes.Equal(chunks[0], []byte{1, 2, 3}) ||
		!bytes.Equal(chunks[1], []byte{4, 5, 6}) ||
		!bytes.Equal(chunks[2], []byte{7}) {
		t.Errorf("TestSplitBytes: Unexpected result: %v", chunks)
	}
}
