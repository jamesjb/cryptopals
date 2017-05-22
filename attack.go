package cryptopals

import (
	"sort"
	"unicode"
)

// ScorePlaintext returns a numeric score representation of how likely
// a string is to be English text (with higher values indicating a
// higher statistical probability.)
func ScorePlaintext(s string) float32 {
	result := 0

	for i := range s {
		r := rune(s[i]) // assume string is ASCII, not UTF-8
		if unicode.IsLetter(r) {
			switch unicode.ToUpper(r) {
			case 'E', 'T', 'A', 'O', 'I', 'N', ' ':
				result += 2
			case 'S', 'H', 'R', 'D', 'L', 'U':
				result++
			}
		} else if !unicode.IsPrint(r) {
			result-- // penalize non-printable characters
		}
	}

	return float32(result) / float32(len(s))
}

// AttackSingleByteXor uses frequency analysis to guess the key of a ciphertext
// that has been XOR'ed with a single byte. Returns the most likely key and the
// score of the plaintext for that key.
func AttackSingleByteXor(ct []byte) (byte, float32) {
	highScore := float32(0.0)
	highScoreKey := byte(0)

	for k := 0; k < 0x100; k++ {
		pt := SingleByteXor(ct, byte(k))
		score := ScorePlaintext(string(pt))
		if score > highScore {
			highScore = score
			highScoreKey = byte(k)
		}
	}

	return highScoreKey, highScore
}

type keysizeStats struct {
	KeySize           int
	NormalizedHamming float32
}

// NormalizedHammingDistanceForKeysize calculates the normalized Hamming
// distance from a ciphertext with a given guess at a keysize. The number
// of rounds specifies how many key-length blocks are averaged out into
// the final result.
func NormalizedHammingDistanceForKeysize(ct []byte, keysize, rounds int) float32 {
	totalDist := float32(0.0)
	for i := 0; i < rounds; i++ {
		slice1 := ct[keysize*(i+0) : keysize*(i+1)]
		slice2 := ct[keysize*(i+1) : keysize*(i+2)]
		totalDist += float32(HammingDistance(slice1, slice2)) / float32(keysize)
	}
	return totalDist / float32(rounds)
}

// AttackRepeatingXorForKeysize does frequency analysis on strides of
// ciphertext by keysize to guess the best key.
func AttackRepeatingXorForKeysize(ct []byte, keysize int) []byte {
	blocks := TransposeBytes(ct, keysize)
	key := make([]byte, keysize)

	for i, blockBytes := range blocks {
		k, _ := AttackSingleByteXor(blockBytes)
		key[i] = k
	}

	return key
}

// AttackRepeatingXor uses statistical methods to guess the key for a
// ciphertext encrypted with "repeating key XOR".
func AttackRepeatingXor(ct []byte) []byte {
	keysizes := []keysizeStats{}
	maxKeysize := 40

	if maxKeysize > len(ct)/2 {
		maxKeysize = len(ct) / 2
	}

	for i := 1; i <= maxKeysize; i++ {
		dist := NormalizedHammingDistanceForKeysize(ct, i, len(ct)/i-1)
		keysizes = append(keysizes, keysizeStats{i, dist})
	}

	sort.Slice(keysizes, func(i int, j int) bool {
		return keysizes[i].NormalizedHamming < keysizes[j].NormalizedHamming
	})

	return AttackRepeatingXorForKeysize(ct, keysizes[0].KeySize)
}
