package main

import (
	"fmt"

	"github.com/glennzw/fishcrypt"
)

func main() {

	secretData := "Meet me at the docks at noon"
	myPassword := "thequickbrownfox"
	myNewPassword := "theslowwhiterabbit"

	fmt.Printf("[+] Plaintext: '%s'\n", secretData)
	fmt.Printf("[+] Password: %s\n", myPassword)

	fmt.Println("\n[+] Generating keys")
	pubKey, privKey, _ := fishcrypt.CreateKeys(myPassword)

	fmt.Printf("[+] Private Key (encrypted): %s\n", privKey)
	fmt.Printf("[+] Public Key: %s\n", pubKey)
	encData, _ := fishcrypt.EncryptData(secretData, pubKey)

	decPrivKey, err := fishcrypt.DecryptPrivateKey(privKey, myPassword)
	if err != nil {
		panic(err)
	}

	fmt.Printf("\n[+] Decrypting Private Key with password '%s'\n", myPassword)
	decData, err := fishcrypt.DecryptData(encData, decPrivKey)

	//decData, err := fishcrypt.DecryptData(encData, myPassword, privKey, pubKey)
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Printf("[+] Data decrypted with Private Key: '%s'\n", decData)
	}

	// Keep the same private key, but wrap it in a new password
	fmt.Printf("\n[+] Changing private key password to '%s'\n", myNewPassword)
	newPrivKey, err := fishcrypt.UpdatePassword(privKey, myPassword, myNewPassword)
	if err != nil {
		panic(err)
	}
	fmt.Printf("[+] Private Key (encrypted with new password): %s\n", newPrivKey)
	fmt.Printf("[+] Public Key: %s\n", pubKey)

	decPrivKey, err = fishcrypt.DecryptPrivateKey(newPrivKey, myNewPassword)
	if err != nil {
		panic(err)
	}

	fmt.Printf("\n[+] Decrypting Private Key with new password '%s'\n", myNewPassword)
	decData, err = fishcrypt.DecryptData(encData, decPrivKey)
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Printf("[+] Data decrypted with Private Key: '%s'\n", decData)
	}

}
