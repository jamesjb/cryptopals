package cryptopals

import (
	"encoding/base64"
	"io/ioutil"
)

// ReadFileBase64 reads the contents of a base64 encoded file into a
// byte slice and returns it.
func ReadFileBase64(filename string) ([]byte, error) {
	bytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	return base64.StdEncoding.DecodeString(string(bytes))
}

// XorBytes computes the bytewise exclusive-OR of two equal length
// byte slices, returning the result in a new slice.
func XorBytes(a, b []byte) []byte {
	if len(a) != len(b) {
		panic("XorBytes: slices are not the same length")
	}

	result := make([]byte, len(a))
	for i := range a {
		result[i] = a[i] ^ b[i]
	}

	return result
}

// TransposeBytes creates a two-dimensional slice from a one-dimensional
// slice given a stride length.
func TransposeBytes(xs []byte, n int) [][]byte {
	result := make([][]byte, n)
	for i, b := range xs {
		result[i%n] = append(result[i%n], b)
	}
	return result
}

// SplitBytes breaks up a byte slice into chunks, each the same length.
func SplitBytes(xs []byte, n int) [][]byte {
	result := [][]byte{}
	for i := 0; i < len(xs); i += n {
		end := i + n
		if i+n > len(xs) {
			end = len(xs)
		}
		result = append(result, xs[i:end])
	}
	return result
}

// DuplicateChunks counts the number of duplicate elements in an
// array of byte slices. Go's lack of generics really hurts here...
func DuplicateChunks(chunks [][]byte) int {
	seen := map[string]int{}
	maxSeen := 0

	for _, chunk := range chunks {
		s := string(chunk)
		n, ok := seen[s]

		if ok {
			seen[s] = n + 1
		} else {
			seen[s] = 1
		}

		if seen[s] > maxSeen {
			maxSeen = seen[s]
		}
	}

	return maxSeen
}

// SingleByteXor "encrypts" a byte slice by repeatedly XORing each
// byte with a single key byte, returning the result in a new slice.
func SingleByteXor(pt []byte, k byte) []byte {
	result := make([]byte, len(pt))
	for i := range pt {
		result[i] = pt[i] ^ k
	}
	return result
}

// RepeatingXor "encrypts" a byte slice by repeatedly XORing each
// byte with a repeating key, returning the result in a new slice.
func RepeatingXor(pt []byte, k []byte) []byte {
	result := make([]byte, len(pt))
	for i := range pt {
		result[i] = pt[i] ^ k[i%len(k)]
	}
	return result
}

// PopCount returns the number of set bits in a byte.
func PopCount(x byte) int {
	result := 0
	for i := uint(0); i < 8; i++ {
		if x&(1<<i) != 0 {
			result++
		}
	}
	return result
}

// HammingDistance returns the number of bits that differ between
// two byte slices of the same length.
func HammingDistance(a, b []byte) int {
	if len(a) != len(b) {
		panic("HammingDistance: slices are not the same length")
	}

	result := 0
	for i := range a {
		result += PopCount(a[i] ^ b[i])
	}
	return result
}
