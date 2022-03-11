import logging
import random
import string
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from hmac import digest_size
from cryptography.hazmat.primitives.asymmetric import dsa

# Generating text file taking file name and number of bytes as input. 
def generate_text_file(filename, size):
    logging.info('\n ***********************************************')
    logging.info('Generating text file ' + filename)
    c = ''.join([random.choice(string.ascii_letters) for i in range(0, size * 1024)])
    with open(filename, 'w') as f_open:
        f_open.write(c)
    logging.info('Text file generated')
    pass

# AES CBC using 128 bit key.
class AES_CBC:
    def __init__(self):
        key = os.urandom(16)
        iv = os.urandom(16)
        aes = Cipher(algorithm=algorithms.AES(key),mode=modes.CBC(iv),backend=default_backend())
        self.encryptor = aes.encryptor()
        self.decryptor = aes.decryptor()

    def update_encryptor(self, plaintext):
        return self.encryptor.update(plaintext)

    def update_decryptor(self, ciphertext):
        return self.decryptor.update(ciphertext)

def aes_cbc_128(filename):

    key_start = time.time_ns()
    manager = AES_CBC()
    key_end = time.time_ns() - key_start
    logging.info('AES CBC: Time taken to generate key for ' + filename + ' is '+ str(key_end))

    with open(filename, 'rb') as open_file:
        file_read = open_file.read()

    enc_start = time.time_ns()
    cipher_text = manager.update_encryptor(file_read)
    enc_end = time.time_ns() - enc_start
    logging.info('AES CBC: Time taken for encrypting ' + filename + ' is '+ str(enc_end))

    dec_start = time.time_ns()
    recovered_message = manager.update_decryptor(cipher_text)
    dec_end = time.time_ns() - dec_start
    logging.info('AES CBC: Time taken for decrypting ' + filename + ' is '+ str(dec_end))

    verify = recovered_message == file_read
    logging.info('AES CBC: Is ' + filename + 'decrypted properly? : ' + str(verify))

    logging.info('AES CBC: Encryption speed per byte for ' + filename + ' : ' + str(enc_end/len(file_read)))
    logging.info('AES CBC: Decryption speed per byte for ' + filename + ' : ' + str(dec_end/len(file_read)))

# AES CTR using 128 bit key.
class AES_CTR:
    def __init__(self):
        key = os.urandom(16)
        iv = os.urandom(16)
        aes = Cipher(algorithm=algorithms.AES(key),mode=modes.CTR(iv),backend=default_backend())
        self.encryptor = aes.encryptor()
        self.decryptor = aes.decryptor()

    def update_encryptor(self, plaintext):
        return self.encryptor.update(plaintext)

    def update_decryptor(self, ciphertext):
        return self.decryptor.update(ciphertext)

def aes_ctr_128(filename):
    key_start = time.time_ns()
    manager = AES_CTR()
    key_end = time.time_ns() - key_start
    logging.info('AES CTR: Time taken to generate key for ' + filename + ' is '+ str(key_end))

    with open(filename, 'rb') as open_file:
        file_read = open_file.read()

    enc_start = time.time_ns()
    cipher_text = manager.update_encryptor(file_read)
    enc_end = time.time_ns() - enc_start
    logging.info('AES CTR: Time taken for encrypting ' + filename + ' is '+ str(enc_end))

    dec_start = time.time_ns()
    recovered_message = manager.update_decryptor(cipher_text)
    dec_end = time.time_ns() - dec_start
    logging.info('AES CTR: Time taken for decrypting ' + filename + ' is '+ str(dec_end))

    verify = recovered_message == file_read
    logging.info('AES CTR: Is ' + filename + 'decrypted properly? : ' + str(verify))

    logging.info('AES CTR: Encryption speed per byte for ' + filename + ' : ' + str(enc_end/len(file_read)))
    logging.info('AES CTR: Decryption speed per byte for ' + filename + ' : ' + str(dec_end/len(file_read)))

# AES CTR with 256 bit key. 
class AES_CTR_256:
    def __init__(self):
        key = os.urandom(32)
        iv = os.urandom(16)
        aes = Cipher(algorithm=algorithms.AES(key),mode=modes.CTR(iv),backend=default_backend())
        self.encryptor = aes.encryptor()
        self.decryptor = aes.decryptor()

    def update_encryptor(self, plaintext):
        return self.encryptor.update(plaintext)

    def update_decryptor(self, ciphertext):
        return self.decryptor.update(ciphertext)

def aes_ctr_256(filename):
    key_start = time.time_ns()
    manager = AES_CTR_256()
    key_end = time.time_ns() - key_start
    logging.info('AES CTR 256: Time taken to generate key for ' + filename + ' is '+ str(key_end))

    with open(filename, 'rb') as open_file:
        file_read = open_file.read()

    enc_start = time.time_ns()
    cipher_text = manager.update_encryptor(file_read)
    enc_end = time.time_ns() - enc_start
    logging.info('AES CTR 256: Time taken for encrypting ' + filename + ' is '+ str(enc_end))

    dec_start = time.time_ns()
    recovered_message = manager.update_decryptor(cipher_text)
    dec_end = time.time_ns() - dec_start
    logging.info('AES CTR 256: Time taken for decrypting ' + filename + ' is '+ str(dec_end))

    verify = recovered_message == file_read
    logging.info('AES CTR 256: Is ' + filename + 'decrypted properly? : ' + str(verify))

    logging.info('AES CTR 256: Encryption speed per byte for ' + filename + ' : ' + str(enc_end/len(file_read)))
    logging.info('AES CTR 256: Decryption speed per byte for ' + filename + ' : ' + str(dec_end/len(file_read)))

# RSA using 2048 bit key 
def rsa_2048(filename):
    with open(filename, 'rb') as open_file:
        file_read = open_file.read()

    key_start = time.time_ns()
    priv_key = rsa.generate_private_key(public_exponent =  65537, key_size = 2048)
    pub_key = priv_key.public_key()
    key_end = time.time_ns() - key_start
    logging.info('RSA 2048: Time taken to generate key for ' + filename + ' is ' + str(key_end))

    s = 0
    ciphertxt = []
    enc_start = time.time_ns()
    while 1:
        f = file_read[s*128:(s+1)*128]
        if not f: 
            break
        cipher_text = pub_key.encrypt(
            f, 
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
                )
            )
        ciphertxt.append(cipher_text)
        s+=1    
    enc_end = time.time_ns() - enc_start
    logging.info('RSA 2048: Time taken for encrypting ' + filename + ' is ' + str(enc_end))


    s = 0
    recovered_msg = ""
    dec_start = time.time_ns()
    for c in ciphertxt:
        rec = priv_key.decrypt(
            c, 
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
                )
            )
        recovered_msg+=str(rec.decode())
    dec_end = time.time_ns() - dec_start
    logging.info('RSA 2048: Time taken for decrypting ' + filename + ' is ' + str(dec_end))

    verify = file_read.decode() == recovered_msg
    logging.info('RSA 2048: Is ' + filename + 'decrypted properly? : ' + str(verify))

    logging.info('RSA 2048: Encryption speed per byte for ' + filename + ' : ' + str(enc_end/len(file_read)))
    logging.info('RSA 2048: Decryption speed per byte for ' + filename + ' : ' + str(dec_end/len(file_read)))

# RSA using 3072 bit key 
def rsa_3072(filename):
    with open(filename, 'rb') as open_file:
        file_read = open_file.read()

    key_start = time.time_ns()
    priv_key = rsa.generate_private_key(public_exponent =  65537, key_size = 3072)
    pub_key = priv_key.public_key()
    key_end = time.time_ns() - key_start
    logging.info('RSA 3072: Time taken to generate key for ' + filename + ' is ' + str(key_end))

    s = 0
    ciphertxt = []
    enc_start = time.time_ns()
    while 1:
        f = file_read[s*128:(s+1)*128]
        if not f: 
            break
        cipher_text = pub_key.encrypt(
            f, 
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
                )
            )
        ciphertxt.append(cipher_text)
        s+=1    
    enc_end = time.time_ns() - enc_start
    logging.info('RSA 3072: Time taken for encrypting ' + filename + ' is ' + str(enc_end))


    s = 0
    recovered_msg = ""
    dec_start = time.time_ns()
    for c in ciphertxt:
        rec = priv_key.decrypt(
            c, 
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
                )
            )
        recovered_msg+=str(rec.decode())
    dec_end = time.time_ns() - dec_start
    logging.info('RSA 3072: Time taken for decrypting ' + filename + ' is ' + str(dec_end))

    verify = file_read.decode() == recovered_msg
    logging.info('RSA 3072: Is ' + filename + 'decrypted properly? : ' + str(verify))

    logging.info('RSA 3072: Encryption speed per byte for ' + filename + ' : ' + str(enc_end/len(file_read)))
    logging.info('RSA 3072: Decryption speed per byte for ' + filename + ' : ' + str(dec_end/len(file_read)))

# Hashing using SHA-256, SHA-512, SHA3-256
def hashing(filename):
    with open(filename, 'rb') as open_file:
        file_read = open_file.read()
    
    # SHA-256
    hash_start = time.time_ns()
    digest = hashes.Hash(hashes.SHA256())
    digest.update(file_read)
    sha256 =  str(digest.finalize())
    hash_end = time.time_ns() - hash_start
    logging.info('SHA-256 : Time taken for hashing ' + filename + ' is ' + str(hash_end))
    logging.info('SHA-256 : Generated hash for ' + filename + ' is ' + sha256)
    logging.info('SHA-256 : Hashing speed per byte for ' + filename + ' is ' + str(hash_end/len(file_read)))

    # SHA-512
    hash_start = time.time_ns()
    digest = hashes.Hash(hashes.SHA512())
    digest.update(file_read)
    sha512 =  str(digest.finalize())
    hash_end = time.time_ns() - hash_start
    logging.info('SHA-512 : Time taken for hashing ' + filename + ' is ' + str(hash_end))
    logging.info('SHA-512 : Generated hash for ' + filename + ' is ' + sha512)
    logging.info('SHA-512 : Hashing speed per byte for ' + filename + ' is ' + str(hash_end/len(file_read)))

    # SHA3-256
    hash_start = time.time_ns()
    digest = hashes.Hash(hashes.SHA3_256())
    digest.update(file_read)
    sha3_256 =  str(digest.finalize())
    hash_end = time.time_ns() - hash_start
    logging.info('SHA3-256 : Time taken for hashing ' + filename + ' is ' + str(hash_end))
    logging.info('SHA3-256 : Generated hash for ' + filename + ' is ' + sha3_256)
    logging.info('SHA3-256 : Hashing speed per byte for ' + filename + ' is ' + str(hash_end/len(file_read)))

# DSA using 2048 bit key. 
def dsa_signing(filename):
    with open(filename, 'rb') as f_open:
        file_read = f_open.read()

    key_start = time.time_ns()
    priv_key = dsa.generate_private_key(2048)
    pub_key = priv_key.public_key()
    key_end = time.time_ns() - key_start
    logging.info('DSA 2048: Time taken to generate key for ' + filename + ' is ' + str(key_end))

    sign_start = time.time_ns()
    signature = priv_key.sign(file_read, algorithm=hashes.SHA256())
    sign_end = time.time_ns() - sign_start
    logging.info('DSA 2048: Time taken for signing ' + filename + ' is ' + str(sign_end))

    verify_start = time.time_ns()
    pub_key.verify(signature, file_read, algorithm=hashes.SHA256())
    verify_end = time.time_ns() - verify_start
    logging.info('DSA 2048: Time taken for verifying the signature for ' + filename + ' is ' + str(verify_end))

    logging.info('DSA 2048: Signing speed per byte for ' + filename + ' is ' + str(sign_end/len(file_read)))
    logging.info('DSA 2048: Verification speed per byte for ' + filename + ' is ' + str(verify_end/len(file_read)))

# DSA using 3072 bit key. 
def dsa_signing_3072(filename):
    with open(filename, 'rb') as f_open:
        file_read = f_open.read()

    key_start = time.time_ns()
    priv_key = dsa.generate_private_key(3072)
    pub_key = priv_key.public_key()
    key_end = time.time_ns() - key_start
    logging.info('DSA 3072: Time taken to generate key for ' + filename + ' is ' + str(key_end))

    sign_start = time.time_ns()
    signature = priv_key.sign(file_read, algorithm=hashes.SHA256())
    sign_end = time.time_ns() - sign_start
    logging.info('DSA 3072: Time taken for signing ' + filename + ' is ' + str(sign_end))

    verify_start = time.time_ns()
    pub_key.verify(signature, file_read, algorithm=hashes.SHA256())
    verify_end = time.time_ns() - verify_start
    logging.info('DSA 3072: Time taken for verifying the signature for ' + filename + ' is ' + str(verify_end))

    logging.info('DSA 3072: Signing speed per byte for ' + filename + ' is ' + str(sign_end/len(file_read)))
    logging.info('DSA 3072: Verification speed per byte for ' + filename + ' is ' + str(verify_end/len(file_read)))



# Main function.
def main():
    logging.basicConfig(filename='cryptotools.log', level=logging.INFO)
    generate_text_file('small_text_file.txt', 1)
    generate_text_file('large_text_file.txt', 10240)
    generate_text_file('medium_text_file.txt', 1024)
    aes_cbc_128('small_text_file.txt')
    aes_cbc_128('large_text_file.txt')
    aes_ctr_128('small_text_file.txt')
    aes_ctr_128('large_text_file.txt')
    aes_ctr_256('small_text_file.txt')
    aes_ctr_256('large_text_file.txt')
    rsa_2048('small_text_file.txt')
    rsa_2048('medium_text_file.txt')
    rsa_3072('small_text_file.txt')
    rsa_3072('medium_text_file.txt')
    hashing('small_text_file.txt')
    hashing('large_text_file.txt')
    dsa_signing('small_text_file.txt')
    dsa_signing('large_text_file.txt')
    dsa_signing_3072('small_text_file.txt')
    dsa_signing_3072('large_text_file.txt')

if __name__ == '__main__':
    main()