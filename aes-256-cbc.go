// (c) Gon Y. Yi 2021 <https://gonyyi.com/copyright>
// Last Update: 11/12/2021

// AES256CBC is for OpenSSL's aes-256-cbc encoding with MD5 key digest
// This is compatible with:
// - `echo "hello" | openssl enc -e -aes-256-cbc -a -k "PASSWORD" | openssl enc -d -aes-256-cbc -a -k "PASSWORD"`
// - `echo "hello" | openssl enc -e -aes-256-cbc -md md5 -a -k "PASSWORD" | openssl enc -d -aes-256-cbc -a -k "PASSWORD"`
// - `echo "hello" | openssl enc -e -aes-256-cbc -md md5 -a -k "PASSWORD" | openssl enc -d -aes-256-cbc -md md5 -a -k "PASSWORD"`

package aes256cbc

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"github.com/gonyyi/gosl"
	"io"
)

var (
	ERR_BAD_DATA  = gosl.NewError("bad data")
	ERR_BAD_BLOCK = gosl.NewError("bad block")
	ERR_BAD_SALT  = gosl.NewError("bad salt")
	ERR_BAD_PAD   = gosl.NewError("bad pad")
)

func Base64Decrypt(base64Data, key []byte) (out []byte, err error) {
	decoded, err := DecodeBase64(base64Data)
	if err != nil {
		return nil, err
	}
	return Decrypt(decoded, key)
}

// Base64Encrypt will encrypt. If salt is not given, it will randomly generated
func Base64Encrypt(data, key, salt []byte) (outBase64 []byte, err error) {
	out, err := Encrypt(data, key, salt)
	if err != nil {
		return nil, err
	}
	return EncodeBase64(out), nil
}

// Encrypt will encrypt. If salt is not given, it will randomly generated
func Encrypt(data, key, salt []byte) (out []byte, err error) {
	defer gosl.IfPanic("Encrypt", func(a interface{}) {
		out = nil
		if e, ok := a.(error); ok {
			err = e	
		}
	})

	if salt == nil {
		salt = make([]byte, 8)
		if _, err = io.ReadFull(rand.Reader, salt); err != nil {
			return nil, err
		}
	}

	if lenSalt := len(salt); lenSalt < 8 {
		salt = append(salt, make([]byte, 8)...)[:8]
	}
	k, iv := keySaltToKeyIV(key, salt)
	packet := prepData(data, salt)
	enc, err := encData(packet, k, iv)
	if err != nil {
		return nil, err
	}
	return enc, nil
}

func Decrypt(data, key []byte) (out []byte, err error) {
	defer gosl.IfPanic("Decrypt", func(a interface{}) {
		out = nil
		if e, ok := a.(error); ok {
			err = e	
		}
	})
	if len(data) < aes.BlockSize {
		return nil, ERR_BAD_BLOCK
	}
	saltHeader := data[:aes.BlockSize]
	if string(saltHeader[:8]) != "Salted__" {
		return nil, ERR_BAD_SALT
	}
	salt := saltHeader[8:]

	newKey, iv := keySaltToKeyIV(key, salt)
	return decrypt(newKey, iv, data)
}

// EncodeBase64 takes a byte slices and encode it
func EncodeBase64(b []byte) []byte {
	out := make([]byte, base64.StdEncoding.EncodedLen(len(b)))
	base64.StdEncoding.Encode(out, b)
	return out
}

// DecodeBase64 takes base64 encoded byte slices and decode it
func DecodeBase64(b []byte) ([]byte, error) {
	out := make([]byte, base64.StdEncoding.DecodedLen(len(b)))
	n, err := base64.StdEncoding.Decode(out, b)
	if err != nil {
		return nil, err
	}
	return out[0:n], nil
}

func decrypt(key, iv, data []byte) (out []byte, err error) {
	lenData := len(data)
	if lenData == 0 || lenData%aes.BlockSize != 0 {
		return nil, ERR_BAD_BLOCK
	}
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	cipher.NewCBCDecrypter(c, iv).CryptBlocks(data[aes.BlockSize:], data[aes.BlockSize:])
	return unpadPKCS7(data[aes.BlockSize:])
}

func prepData(plainData, salt []byte) []byte {
	data := make([]byte, len(plainData)+aes.BlockSize)
	copy(data[0:], "Salted__") // openssl
	copy(data[8:], salt)
	copy(data[aes.BlockSize:], plainData)
	return data
}

func keySaltToKeyIV(pwd, salt []byte) (key, iv []byte) {
	var m []byte
	prev := []byte{}
	for len(m) < 48 {
		a := make([]byte, len(prev)+len(pwd)+len(salt))
		copy(a, prev)
		copy(a[len(prev):], pwd)
		copy(a[len(prev)+len(pwd):], salt)

		tmp := md5.Sum(a)
		prev = tmp[:]
		m = append(m, prev...)
	}
	return m[:32], m[32:48]
}

func encData(data, key, iv []byte) (out []byte, err error) {
	padded := padPKCS7(data)
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	cbc := cipher.NewCBCEncrypter(c, iv)
	cbc.CryptBlocks(padded[aes.BlockSize:], padded[aes.BlockSize:])
	return padded, nil
}

func padPKCS7(data []byte) []byte {
	lenPad := 1
	lenData := len(data)
	for (lenData+lenPad)%aes.BlockSize != 0 {
		lenPad++
	}
	return append(data, bytes.Repeat([]byte{byte(lenPad)}, lenPad)...)
}

func unpadPKCS7(data []byte) (out []byte, err error) {
	lenData := len(data)
	if lenData == 0 || lenData%aes.BlockSize != 0 {
		return nil, ERR_BAD_DATA
	}
	lenPad := int(data[lenData-1])
	if lenPad > aes.BlockSize || lenPad == 0 {
		return nil, ERR_BAD_BLOCK
	}
	pad := data[lenData-lenPad:]
	for i := 0; i < lenPad; i++ {
		if pad[i] != byte(lenPad) {
			return nil, ERR_BAD_PAD
		}
	}
	return data[:lenData-lenPad], nil
}
