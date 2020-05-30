package utils

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
)

func parseKeyFromPEM(pemFile string, private bool) (interface{}, error) {
	pemFileContents, err := ioutil.ReadFile(pemFile)
	if err != nil {
		return nil, fmt.Errorf("Couldn't read pem file contents. err=%s", err)
	}

	nextBytes := pemFileContents
	for len(nextBytes) > 0 {
		block, rbytes := pem.Decode(nextBytes)
		if block == nil {
			return nil, errors.New("Failed to parse PEM block")
		}

		var err error
		var key interface{}

		if private {
			if block.Type == "PRIVATE KEY" {
				key, err = x509.ParsePKCS8PrivateKey(block.Bytes)

			} else if block.Type == "EC PRIVATE KEY" {
				key, err = x509.ParseECPrivateKey(block.Bytes)

			} else if block.Type == "RSA PRIVATE KEY" {
				key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
			}

		} else {
			if block.Type == "PUBLIC KEY" {
				key, err = x509.ParsePKIXPublicKey(block.Bytes)
			}
			if block.Type == "RSA PUBLIC KEY" {
				key, err = x509.ParsePKCS1PublicKey(block.Bytes)
			}
		}

		if err != nil {
			return nil, err
		}
		if key != nil {
			return key, nil
		}
		nextBytes = rbytes
	}
	if private {
		return nil, fmt.Errorf("Couldn't find key 'PRIVATE KEY' block in PEM file")
	}
	return nil, fmt.Errorf("Couldn't find key 'PUBLIC KEY' block in PEM file")
}
