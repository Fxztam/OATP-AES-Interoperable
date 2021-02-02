package main
import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
)

// --- 30.01.2021 -------------------------------------------
// Interoperable: OracleATP - Web Crypto API (JS) - Golang
// Result: 01eb8015f319bda885939d265c4a38a0
// Friedhold Matz - 2021-JAN
// ----------------------------------------------------------

func main() {
	key := "12345678123456781234567812345678"
	iv := "1234567812345678"
	plaintext := "Hello, World!"
	fmt.Printf("Result: %v\n", Ase256(plaintext, key, iv, aes.BlockSize))
}

func Ase256(plaintext string, key string, iv string, blockSize int) string {
	bKey := []byte(key)
	bIV := []byte(iv)
	bPlaintext := PKCS5Padding([]byte(plaintext), blockSize, len(plaintext))
	block, _ := aes.NewCipher(bKey)
	ciphertext := make([]byte, len(bPlaintext))
	mode := cipher.NewCBCEncrypter(block, bIV)
	mode.CryptBlocks(ciphertext, bPlaintext)
	return hex.EncodeToString(ciphertext)
}

func PKCS5Padding(ciphertext []byte, blockSize int, after int) []byte {
	padding := (blockSize - len(ciphertext)%blockSize)
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}
