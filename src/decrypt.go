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
	"time"
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
	fmt.Println("Enter ciphertext:")
	reader := bufio.NewReader(os.Stdin)
	var aeskey = []byte("321423u9y8d2fwfl")

	ciphertext, _ := reader.ReadString('\n')
	ciphertext = strings.ReplaceAll(ciphertext, "\n", "")
	ciphertext = strings.ReplaceAll(ciphertext, "\r", "")

	bytesPass, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		fmt.Println(err)
		return
	}

	tpass, err := AesDecrypt(bytesPass, aeskey)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("=========================")
	fmt.Printf("Decrypt...\n")
	fmt.Println("=========================")
	time.Sleep(time.Duration(1) * time.Second)
	fmt.Printf("%s    <-- plaintext %T\n\n", tpass, tpass)

	fmt.Print("Press 'Enter' to leave...")
	bufio.NewReader(os.Stdin).ReadBytes('\n')

}
