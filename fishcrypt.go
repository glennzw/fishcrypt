package fishcrypt

//TODO: Functionality to regenerate keys whilst preserving data

import (
	crypto_rand "crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"strings"

	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/secretbox"
)

// UpdatePassword sets a new password protecting the supplied private key
// The private key encrypted with the new password is returned, provided the correct password has been supplied
func UpdatePassword(encPrivKey, oldpassword, newpassword string) (string, error) {

	encodedPublicKey, decPrivKey, err := unpackPrivateKey(encPrivKey, oldpassword)
	if err != nil {
		return "", err
	}

	// Encrypt private key with new password
	encryptedPrivateKey, err := encryptPrivateKey(&decPrivKey, newpassword)

	// Encode private key to base64
	encodedPrivateKey := base64.StdEncoding.EncodeToString(encryptedPrivateKey)

	// Pack private key
	//encodedPrivateKey, err := packPrivateKey(publicKey, encryptPrivateKey)
	encodedEncryptedPrivateKeyPair := encodedPublicKey + "|" + encodedPrivateKey // We combine them as we need both keys when decrypting data
	combinedEncodedKeyPair := base64.StdEncoding.EncodeToString([]byte(encodedEncryptedPrivateKeyPair))

	return combinedEncodedKeyPair, nil
}

// CreateKeys creates a public and private pair of keys. The private key is encrypted with the supplied password.
func CreateKeys(password string) (string, string, error) {

	// Create public and private keys for user
	publicKey, privateKey, err := box.GenerateKey(crypto_rand.Reader)
	if err != nil {
		return "", "", err
	}

	// Encrypty private key with supplied password
	encryptedPrivateKey, err := encryptPrivateKey(privateKey, password)

	// Encode public key and encrypted private key to Base64
	encodedPublicKey := base64.StdEncoding.EncodeToString(publicKey[:])
	encodedPrivateKey := base64.StdEncoding.EncodeToString(encryptedPrivateKey)

	encodedEncryptedPrivateKeyPair := encodedPublicKey + "|" + encodedPrivateKey // We combine them as we need both keys when decrypting data
	combinedEncodedKeyPair := base64.StdEncoding.EncodeToString([]byte(encodedEncryptedPrivateKeyPair))

	return encodedPublicKey, combinedEncodedKeyPair, nil
}

// EncryptData encrypts the supplied data with the supplied publicKey
func EncryptData(data, pubKey string) (string, error) {

	encodedPublicKey := pubKey

	publicKey, err := decodeKey(encodedPublicKey)
	if err != nil {
		return "", err
	}

	// Encrypt data with public key
	encrypted, err := box.SealAnonymous(nil, []byte(data), &publicKey, nil)
	if err != nil {
		return "", err
	}

	// Encode encrypted data to base64 in order to save to database
	encodedData := base64.StdEncoding.EncodeToString(encrypted)

	return encodedData, nil
}

// DecryptPrivateKey decrypts the private key with the supplied password
func DecryptPrivateKey(privKey, password string) (string, error) {

	// Function actually takes the encoded and encrypted private KeyPair and returns the result decrypted
	// Takes: B64(PublicKey) | B64(Enc(PrivateKey)), password
	// Returns: B64(PublicKey) | B64(PrivateKey)

	encodedPublicKey, privateKey, err := unpackPrivateKey(privKey, password)
	if err != nil {
		return "", err
	}

	// Encode the decrypted private key to base64
	encodedPrivateKey := base64.StdEncoding.EncodeToString(privateKey[:])

	// Return the keypair separated by a pipe
	combinedEncodedKeyPair := base64.StdEncoding.EncodeToString([]byte(encodedPublicKey + "|" + encodedPrivateKey))
	return combinedEncodedKeyPair, nil

}

// DecryptData decrypts data with the supplied decrypted private key
// Make sure you have decrypted the private key first with DecryptPrivateKeyPair()
func DecryptData(data, privKey string) (string, error) {

	tmp, err := base64.StdEncoding.DecodeString(privKey)
	encodedKeyPair := string(tmp)

	// Split the public and private components
	pipe := strings.Index(encodedKeyPair, "|")
	if pipe < 1 {
		return "", errors.New("Unable to parse keypair")
	}
	encodedPublicKey := encodedKeyPair[:pipe]
	encodedPrivateKey := encodedKeyPair[pipe+1:]

	// Decode the keypair from base64
	publicKey, err := decodeKey(encodedPublicKey)
	privateKey, err := decodeKey(encodedPrivateKey)
	if err != nil {
		return "", err
	}

	// Decrypt the data with the private key
	encryptedData, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return "", err
	}
	opened, ok := box.OpenAnonymous(nil, encryptedData, &publicKey, &privateKey)
	if !ok {
		return "", errors.New("Error decrypting data")
	}

	return string(opened), nil

}

// decodeKey decodes a base64 encoded key and returns
func decodeKey(encodedKey string) ([32]byte, error) {

	var decodedKey [32]byte = [32]byte{}
	tmp, err := base64.StdEncoding.DecodeString(encodedKey)
	if err != nil {
		return decodedKey, err
	}
	copy(decodedKey[:], tmp)
	return decodedKey, nil
}

// unpackPrivateKey decodes the public private components, decrypts the private key and returns the encoded public and raw private keys
func unpackPrivateKey(privKey, password string) (string, [32]byte, error) {
	tmp, err := base64.StdEncoding.DecodeString(privKey)
	encodedKeyPair := string(tmp)

	// Split the public and private components
	pipe := strings.Index(encodedKeyPair, "|")
	if pipe < 1 {
		return "", [32]byte{}, errors.New("Unable to parse keypair")
	}
	encodedPublicKey := encodedKeyPair[:pipe]
	encodedEncryptedPrivateKey := encodedKeyPair[pipe+1:]

	// Decode the private key from base64
	encryptedPrivateKey, err := base64.StdEncoding.DecodeString(encodedEncryptedPrivateKey)
	if err != nil {
		return "", [32]byte{}, err
	}

	// Decrypt the private key with the supplied password
	secretKeyBytes := []byte(password)
	var secretKey [32]byte
	copy(secretKey[:], secretKeyBytes)

	var decryptNonce [24]byte
	copy(decryptNonce[:], encryptedPrivateKey[:24])
	tmp, ok := secretbox.Open(nil, encryptedPrivateKey[24:], &decryptNonce, &secretKey)
	if !ok {
		return "", [32]byte{}, errors.New("Decryption error. Is the password correct?")
	}
	var privateKey [32]byte
	copy(privateKey[:], tmp)

	return encodedPublicKey, privateKey, nil
}

// encryptPrivateKey encryptes a raw private key with the supplied password and returns the result
func encryptPrivateKey(privateKey *[32]byte, password string) ([]byte, error) {

	secretKeyBytes := []byte(password)
	var secretKey [32]byte
	copy(secretKey[:], secretKeyBytes)
	var nonce [24]byte
	if _, err := io.ReadFull(crypto_rand.Reader, nonce[:]); err != nil {
		return []byte{}, err
	}
	encryptedPrivateKey := secretbox.Seal(nonce[:], privateKey[:], &nonce, &secretKey)
	return encryptedPrivateKey, nil

}
