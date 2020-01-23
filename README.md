# FishCrypt - Database Encryption Utility

Check out a live PoC demo here: https://fishcrypt.herokuapp.com/

## Overview
FishCrypt allows you to encrypt data to be stored in your database (or other data stores) whilst handling the public and private keys. The private key is protected by a password, typically the user's password. All the heavy lifting is done by the Go crypto libraries, FishCrypt just creates some useful wrappers.

There are three points of encryption in most (web) applications; data in transit (use TLS), data at rest (use TDE to encrypt the entire database), and column level encryption. FishCrypt tackles the third point in this triangle, allowing the encryption of a user's data, whereby their private key and password are required to decrypt the data.

## Usage
 
FishCrypt consists of four helper functions to manage keys and encryption:

`CreateKeys`: Create a pair of keys, encrypting the private portion with a supplied password  
`EncryptData`: Encrypt data with a supplied public key  
`DecryptPrivateKey`: Decrypt the supplied private key with the supplied password  
`DecryptData`: Decrypt the supplied data with the supplied private key  
`UpdatePassword`: Update the password protecting a private key (key remains the same)

All keys are returned in Base64 format for easy database storage.

Below is an example of usage.

```
// Create keys when user signs up, and store the public and encrypted private keys in your database
publicKey, encryptedPrivateKey, _ := fishcrypt.CreateKeys(usersPassword)

// Now data for the user can be encrypted with their public key and saved in the database
newData := "some data to encrypt for the user"
encryptedData, _ := fishcrypt.EncryptData(newData, publicKey)

// When the user logs in their password is used to decrypt the private key and store it client side (e.g. as a cookie)
decryptedPrivateKey, _ := fishcrypt.DecryptPrivateKey(encryptedPrivateKey, usersPassword)

// The user can view their decrypted data by submitting their private key and the encrypted data
decryptedData, _ := fishcrypt.DecryptData(encryptedData, decryptedPrivateKey)

```

When the user's password is changed, the private key is simply decrypted with the old password and re-encrypted with the new password (and saved back to the database). For example:

```
newEncryptedPrivateKey, _ := fishcrypt.UpdatePassword(encryptedPrivateKey, oldPassword, newPassword)
```

## Examples

Included in this repository is a command line program as well as a fully functioning PoC web application. With the web application you can register user accounts, send encrypted messages, and decrypt them. The web application is also available online <a href="https://fishcrypt.herokuapp.com">here</a>. You'll notice if you view your cookies that the private key is stored there.

## Implications

This solution is not fool-proof as data is still decrypted on the server side before sending back to the client, so a determined attacker with high privileges on the server could theoretically steal the user's password or decrypted private key from memory, but this is quite difficult.

FishCrypt does, however, protect against garden variety database theft. The more secure alternative would be to use client side key generation and storage (e.g. [WebCryptoAPI](https://www.w3.org/TR/WebCryptoAPI/)), but is a lot of extra overhead. This server side solution keeps things simple, whilst adding a decent layer of protection, and not requiring any special browser capabilities.

## Under the hood
We use the excellent NaCl libraries by Daniel J. Bernstein (djb) to do the heavy lifting. We use `box` to generate the public and private keys, and `secretbox` to encrypt the private key with the user's password. The private key is actually saved with the public component to make decryption easier (as both are required by the `box.Open` function). The FishCrypt keys are of the form:

Public key: `B64(PublicKey)`  
Private key: `B64(PublicKey) | B64(Enc(PrivateKey))`

## Feedback
Any feedback would be appreciated. Maybe there are glaring security risks, or maybe there are already libraries to do this and my Google fu is weak.

## References
https://en.wikipedia.org/wiki/Database_encryption  
https://nacl.cr.yp.to/  
https://godoc.org/golang.org/x/crypto/nacl  



