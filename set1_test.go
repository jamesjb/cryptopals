//
// set1_test.go --- Cryptopals Set1
//
// Copyright (C) 2017, James Bielman
// All Rights Reserved.
//

package cryptopals

import (
	"bufio"
	"crypto/aes"
	"encoding/base64"
	"encoding/hex"
	"os"
	"testing"
)

// Set 1, Challenge 1: Convert hex to base64
func TestHexToBase64(t *testing.T) {
	bytes, _ := hex.DecodeString("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
	base64 := base64.StdEncoding.EncodeToString(bytes)

	if base64 != "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t" {
		t.Errorf("TestHexToBase64: Unexpected base64: %s", base64)
	}
}

// Set 1, Challenge 2: Fixed XOR
func TestFixedXor(t *testing.T) {
	a, _ := hex.DecodeString("1c0111001f010100061a024b53535009181c")
	b, _ := hex.DecodeString("686974207468652062756c6c277320657965")
	c := XorBytes(a, b)

	if hex.EncodeToString(c) != "746865206b696420646f6e277420706c6179" {
		t.Errorf("TestFixedXor: Unexpected result: %v", c)
	}
}

// Set 1, Challenge 3: Single-byte XOR cipher
func TestSingleByteXor(t *testing.T) {
	ct, _ := hex.DecodeString("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
	k, _ := AttackSingleByteXor(ct)
	pt := string(SingleByteXor(ct, k))

	if pt != "Cooking MC's like a pound of bacon" {
		t.Errorf("TestSingleByteXor: Unexpected result: %s", pt)
	}
}

// Set 1, Challenge 4: Detect single-character XOR
func TestDetectSingleByteXor(t *testing.T) {
	file, err := os.Open("data/4.txt")
	if err != nil {
		t.Fatal(err)
	}

	defer file.Close()

	highScore := float32(0.0)
	highScorePlaintext := ""

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		ct, err := hex.DecodeString(scanner.Text())
		if err != nil {
			t.Fatal(err)
		}

		k, score := AttackSingleByteXor(ct)
		if score > highScore {
			highScore = score
			highScorePlaintext = string(SingleByteXor(ct, k))
		}
	}

	if highScorePlaintext != "Now that the party is jumping\n" {
		t.Errorf("TestTestDetectSingleByteXor: Unexpected result: %s", highScorePlaintext)
	}
}

// Set 1, Challenge 5: Implement repeating-key XOR
func TestRepeatingXor(t *testing.T) {
	pt := []byte("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal")
	ct := RepeatingXor(pt, []byte("ICE"))

	if hex.EncodeToString(ct) != "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f" {
		t.Errorf("TestRepeatingXor: Unexpected result: %v", ct)
	}
}

// Set 1, Challenge 6: Break repeating-key XOR
func TestAttackRepeatingXor(t *testing.T) {
	ct, err := ReadFileBase64("data/6.txt")
	if err != nil {
		t.Fatal(err)
	}

	k := string(AttackRepeatingXor(ct))
	if k != "Terminator X: Bring the noise" {
		t.Errorf("TestAttackRepeatingXor: Unexpected result: %s", k)
	}
}

// Set 1, Challenge 7: AES in ECB mode
func TestAESECB(t *testing.T) {
	ct, err := ReadFileBase64("data/7.txt")
	if err != nil {
		t.Fatal(err)
	}

	cipher, err := aes.NewCipher([]byte("YELLOW SUBMARINE"))
	if err != nil {
		t.Fatal(err)
	}

	// assume proper padding
	for i := 0; i < len(ct); i += cipher.BlockSize() {
		cipher.Decrypt(ct[i:], ct[i:])
	}

	s := string(ct[:33])
	if s != "I'm back and I'm ringin' the bell" {
		t.Errorf("TestAESECB: Unexpected result: %s", s)
	}
}

// Set 1, Challenge 8: Detect AES in ECB mode
func TestDetectECB(t *testing.T) {
	file, err := os.Open("data/8.txt")
	if err != nil {
		t.Fatal(err)
	}

	defer file.Close()

	maxDups := 0
	maxDupsCT := ""

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		s := scanner.Text()
		ct, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}

		chunks := SplitBytes(ct, 16)
		dups := DuplicateChunks(chunks)

		if dups > maxDups {
			maxDups = dups
			maxDupsCT = s
		}
	}

	if maxDupsCT != "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a" {
		t.Errorf("TestDetectECB: Unexpected result: %s", maxDupsCT)
	}
}
