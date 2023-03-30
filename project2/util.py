import numpy as np
import hashlib
import random
from OpenSSL import crypto
from Crypto.PublicKey import RSA
from Crypto.Cipher import DES3

seed = 2023
np.random.seed(seed)
random.seed(seed)

def create_certificate(name):
    # create keys to self-sign
    key_pair = crypto.PKey()
    key_pair.generate_key(crypto.TYPE_RSA, 2048)
    # create a self-signed certificate
    cert = crypto.X509()
    cert.set_serial_number(0)
    cert.get_subject().commonName = name #Alice or Bob
    cert.get_issuer().commonName = name #Alice or Bob
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(600) # certificate is valid for 600 seconds
    cert.set_pubkey(key_pair)
    cert.sign(key_pair, "md5")
    return key_pair, cert

def verify_certificate(certificate, expected_name):
    return True if certificate.get_subject().commonName == expected_name else False

def get_publickey(certificate, file_name = "public_key.pem"):
    #I only know this way to extract the key
    #I haven't figure out how to extract the key from the certificate object directly
    #(There are some errors when I extract them)
    public_key_file = open(file_name, "wb+")
    publickey = certificate.get_pubkey()
    public_key_file.write(crypto.dump_publickey(crypto.FILETYPE_PEM, publickey))
    public_key_file.close()
    public_key = RSA.importKey(open(file_name).read())
    return public_key

def get_privatekey(key_pair, file_name = "private_key.pem"):
    private_key_file = open(file_name, "wb+")
    private_key_file.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key_pair))
    private_key_file.close()
    private_key = RSA.importKey(open(file_name).read())
    return private_key

def get_master_secret(s, RA, RB):
    return int(s,2) ^ int(RA,2) ^ int(RB,2)

def generate_keys(master_secret):
    #an intuitive way is to split the secret to 4 keys
    m = hashlib.sha512()
    m.update(pad("{:0b}".format(master_secret), length = 64).encode())
    digest = m.digest()
    key1 = digest[:16] #each block of 3DES is 8 bits long, key = key1 + key2 = 16 bits long
    key2 = digest[16:32]
    key3 = digest[32:48]
    key4 = digest[48:64]
    return key1, key2, key3, key4

def get_hash( string, method = "SHA1"):
    method_list = ["SHA1", "MD5"]
    if method not in method_list:
        raise ValueError("method must be one of the following list: {}".format(method_list))
    
    if method == "SHA1":
        m = hashlib.sha1()
    elif method == "MD5":
        m = hashlib.md5()
    if type(string) is str:
        text = string.encode()
    else: 
        text = string
    m.update(text)
    return m.hexdigest()

hash_for_sign = 'MD5'
def signature(message, private_key):
    hash = get_hash( message, method = hash_for_sign)
    hash_int = int(hash, 16)

    p, q, d = private_key
    n = p*q
    return pow(hash_int, d, n)

def verify(message, signature, public_key):
    hash = get_hash( message, method = hash_for_sign)
    hash_int = int(hash, 16)

    n, e = public_key
    decrypted = pow(signature, e, n)
    return (hash_int == decrypted)

def get_hmac(sequence_num, record_header, data, sign_key):
    m = hashlib.sha256()
    m.update(str(sequence_num).encode())
    m.update(record_header)
    m.update(data)
    m.update(sign_key)
    return m.hexdigest()

#generate a random 64 bit number as nonce
def nonceGenerator(bit: int = 8):
    num = ""
    for _ in range(bit):
        c = str(np.random.randint(2, size=None))
        num += c
    return num

def pad(text, length:int = 8):
    if type(text) == str:
        count = len(text.encode('utf-8'))
    else:
        count = len(text)
    add = (length - (count % length)) % length
    entext = text + ('0' * add)
    return entext

seed = 2023
# encrypt a string and returns bytes
def encrypt(string, key):
    np.random.seed(seed) # make sure that all user use the same initial value
    IV = nonceGenerator(bit = 8).encode() #same as one block of key1 key2 
    cipher = DES3.new(key, DES3.MODE_CBC, IV)
    return cipher.encrypt(string)

# decrypt bytes and returns bytes
def decrypt(string, key):
    np.random.seed(seed) # make sure that all user use the same initial value
    IV = nonceGenerator(bit = 8).encode() #same as one block of key1 key2 
    cipher = DES3.new(key, DES3.MODE_CBC, IV)
    return cipher.decrypt(string)