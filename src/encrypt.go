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
	fmt.Println("=========================")
	fmt.Printf("Encrypt...\n")
	fmt.Println("=========================")
	time.Sleep(time.Duration(1) * time.Second)
	fmt.Printf("%s    <-- ciphertext %T\n\n", pass64, pass64)

	fmt.Print("Press 'Enter' to leave...")
	bufio.NewReader(os.Stdin).ReadBytes('\n')

}
