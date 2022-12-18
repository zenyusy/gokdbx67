package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"

	"golang.org/x/term"
)

// AES decrypt body
func decBody(hdr *header, fp *os.File, keyFile string) ([]byte, error) {
	userKey, uerr := compKey(keyFile)
	if uerr != nil {
		return nil, uerr
	}
	rolledKey, rerr := roll(userKey, hdr.rounds, hdr.keyAES, hdr.seed)
	if rerr != nil {
		return nil, rerr
	}
	cip, cerr := aes.NewCipher(rolledKey)
	if cerr != nil {
		return nil, fmt.Errorf("AES by user key: %v", cerr)
	}

	mode := cipher.NewCBCDecrypter(cip, hdr.iv)
	if lenMAC := len(hdr.mac); lenMAC != 0 {
		mac := make([]byte, lenMAC)
		if n, ferr := fp.Read(mac); ferr != nil {
			return nil, fmt.Errorf("read MAC: %v", ferr)
		} else if n != lenMAC {
			return nil, fmt.Errorf("MAC len expect %d got %d", lenMAC, n)
		}
		mode.CryptBlocks(mac, mac)
		if string(mac) != string(hdr.mac) {
			return nil, errors.New("cannot verify MAC")
		}
	}

	ret, err := io.ReadAll(fp)
	if err != nil {
		return nil, fmt.Errorf("read kdb: %v ", err)
	}
	mode.CryptBlocks(ret, ret)
	return ret, nil
}

// compose key from input + file
func compKey(keyFile string) ([]byte, error) {
	h := sha256.New()

	fmt.Print("Password: ")
	password, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Printf("\n")
	if err != nil {
		return nil, fmt.Errorf("getpass: %v", err)
	}
	if len(password) != 0 { // empty = no password
		addressable := sha256.Sum256(password)
		h.Write(addressable[:])
	}

	if len(keyFile) != 0 {
		fpKeyFile, err := os.Open(keyFile)
		if err != nil {
			return nil, fmt.Errorf("open key file %s: %v", keyFile, err)
		}
		defer fpKeyFile.Close()

		h_ := sha256.New()
		if _, err := io.Copy(h_, fpKeyFile); err != nil {
			return nil, fmt.Errorf("read key file %s: %v", keyFile, err)
		} else {
			h.Write(h_.Sum(nil))
		}
	}

	return h.Sum(nil), nil
}

func roll(key []byte, rounds uint64, rollKey []byte, seed []byte) ([]byte, error) {
	cip, err := aes.NewCipher(rollKey)
	if err != nil {
		return nil, fmt.Errorf("AES roll: %v", err)
	}

	keyTail := key[16:32]
	for ; rounds != 0; rounds-- {
		cip.Encrypt(keyTail, keyTail)
		cip.Encrypt(key, key)
	}

	h := sha256.New()
	h.Write(seed)
	addressable := sha256.Sum256(key)
	h.Write(addressable[:])
	return h.Sum(nil), nil
}
