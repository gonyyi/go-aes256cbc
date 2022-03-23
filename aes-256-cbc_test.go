package aes256cbc

import (
	"bytes"
	"testing"
)

func TestEncodeBase64(t *testing.T) {
	longData := `1/5 abcdefghijklmnopqrstuvwzyabcdefghijklmnopqrstuvwzyabcdefghijklmnopqrstuvwzyabcdefghijklmnopqrstuvwzy
2/5 abcdefghijklmnopqrstuvwzyabcdefghijklmnopqrstuvwzyabcdefghijklmnopqrstuvwzyabcdefghijklmnopqrstuvwzy
3/5 abcdefghijklmnopqrstuvwzyabcdefghijklmnopqrstuvwzyabcdefghijklmnopqrstuvwzyabcdefghijklmnopqrstuvwzy
4/5 abcdefghijklmnopqrstuvwzyabcdefghijklmnopqrstuvwzyabcdefghijklmnopqrstuvwzyabcdefghijklmnopqrstuvwzy
5/5 abcdefghijklmnopqrstuvwzyabcdefghijklmnopqrstuvwzyabcdefghijklmnopqrstuvwzyabcdefghijklmnopqrstuvwzy`

	out, err := Base64Encrypt([]byte(longData), []byte("123"), nil)
	if err != nil {
		t.Error(err.Error())
		t.Fail()
	}

	// Make sure even without the space, this can decode
	outDec, err := Base64Decrypt(bytes.ReplaceAll(out, []byte{'\n'}, []byte{}), []byte("123"))
	if err != nil {
		t.Error(err.Error())
		t.Fail()
	}

	if longData != string(outDec) {
		println("Diff")
		println(longData)
		println(string(outDec))
	}
}
