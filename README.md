# unity-crypto

## What is it?
A library containing classes for encrypting and decrypting data.

Features:
* AES encryption and decryption of string (and/or serialized) data

## How to use it.
Call directly from code: SimpleAESEncryption.Encrypt and SimpleAESEncryption.Decrypt

## How does AES encryption work?
When encrypting some plaintext with a password using AES, both encrypted text, and a unique 'IV' (initialisation vector) are produced. 

The IV is a unique 'key' which ensures that the encrypted output is randomised, and refers only to that instance of encrypted output. Otherwise, two inputs starting with the same data, end encrypted with the same password, would have similarities in their encrypted data, making it easier to guess their contents and break the encryption. Most importantly, to decrypt the encrypted data, both the password (which may be shared between multiple inputs), and the IV (which is unique to that instance of encrypted data), are required.

Plaintext + Password --> Encrypted + IV

Encrypted + Password + IV --> Plaintext

### AESEncryptedText
This is a small struct representing some encrypted text, and the IV which was generated when it was encrypted. Both these values must be used when decrypting the encrypted text.