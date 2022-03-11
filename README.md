# cryptography_python
Comparing runtimes and efficiencies of various cryptographic algorithms using Python. 

Library used - Cryptography 36.0.1 
https://pypi.org/project/cryptography/

The code covers encryption and decryption with AES in CBC and CTR mode with 128 and 256 bit keys, RSA with 2048 and 3072 bit keys, hashing with SHA-256, 
SHA-512 and SHA3-256, signing and verification of the signature with DSA 2048 and 3072 bit keys. 

The code can be run in the default terminal or a python supported IDE terminal using the command ./cryptotools. 

The code uses three files for the operations mentioned above, the code to generate the files are included with cryptotools.py. 
The log file generated will capture the following data: 
  1. Time taken to generate the key.
  2. Time taken for encryption/ hashing/ signing the file.
  3. Time taken for decryption/ verification of the signature. 
  4. Per byte speed of encryption/ hashing/ signing. 
  5. Per byte speed of decryption/ verification of the signature. 
