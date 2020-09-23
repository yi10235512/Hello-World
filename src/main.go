package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
)

func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS5UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

func AesEncrypt(origData, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()
	origData = PKCS5Padding(origData, blockSize)
	blockMode := cipher.NewCBCEncrypter(block, key[:blockSize])
	crypted := make([]byte, len(origData))
	blockMode.CryptBlocks(crypted, origData)
	return crypted, nil
}

func AesDecrypt(crypted, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()
	blockMode := cipher.NewCBCDecrypter(block, key[:blockSize])
	origData := make([]byte, len(crypted))
	blockMode.CryptBlocks(origData, crypted)
	origData = PKCS5UnPadding(origData)
	return origData, nil
}

func main() {
	fmt.Println("Enter plaintext:")
	reader := bufio.NewReader(os.Stdin)
	var aeskey = []byte("321423u9y8d2fwfl")
	plaintext, _ := reader.ReadString('\n')
	plaintext = strings.ReplaceAll(plaintext, "\n", "")
	plaintext = strings.ReplaceAll(plaintext, "\r", "")
	b := []byte(plaintext)

	xpass, err := AesEncrypt(b, aeskey)
	if err != nil {
		fmt.Println(err)
		return
	}

	pass64 := base64.StdEncoding.EncodeToString(xpass)
	fmt.Printf("Encrypt...\n%v \n", pass64)

	fmt.Println("Enter ciphertext:")
	ciphertext, _ := reader.ReadString('\n')
	ciphertext = strings.ReplaceAll(ciphertext, "\n", "")
	ciphertext = strings.ReplaceAll(ciphertext, "\r", "")

	bytesPass, err := base64.StdEncoding.DecodeString(ciphertext) //pass64
	if err != nil {
		fmt.Println(err)
		return
	}

	tpass, err := AesDecrypt(bytesPass, aeskey)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("Decrypt...\n%s\n", tpass)
}
