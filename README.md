# Cryptography-Symmetric-File-Encryption
Symmetric encryption of a file using the block cipher AES.

Symmetric encryption of a file using the block cipher AES where the key is derived from a password and a salt.  
The password is encoded using UTF-8. The salt is a randomly generated 128-bit value. The password (p) and salt (s)  is concatenated together (p||s) and is 
hashed 200 times using SHA-256. The resulting digest  (H200(p||s)) is then used as my 256-bit AES key (k).
