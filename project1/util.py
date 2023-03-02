import socket
import numpy as np
from copy import deepcopy

seed = 2023
np.random.seed(seed)

#generate a random 64 bit number as nonce
def nonceGenerator(bit: int = 8):
    num = ""
    for _ in range(bit):
        c = str(np.random.randint(2, size=None))
        num += c
    return num

def pad(text, length:int = 8):
    count = len(text.encode('utf-8'))
    add = (length - (count % length)) % length
    entext = text + ('0' * add)
    return entext

class encrption(object):
    def __init__(self, method = "CBC", bit: int = 64):
        self.bit = bit
        if method == "CBC":
            seed = 2023
            np.random.seed(seed) # make sure that all user use the same initial value
            self.IV = nonceGenerator(bit = 8) #same as one block of key1 key2 
            self.encrypt = self.CBC_encrypt
            self.decrypt = self.CBC_decrypt
        elif method == "ECB":
            self.encrypt = self.ECB_encrypt
            self.decrypt = self.ECB_encrypt #ECB encrypt and decrypt can be the same since I only use xor
        else:
            raise ValueError("method should be 'ECB' or 'CBC'. ")
    
    def split(self, string):
        string = pad(string)
        length = 8 #the length of each block
        results = []
        m = ""
        for i in range(len(string)):
            m += string[i]
            if (i+1) % length == 0:
                results.append(m)
                m = ""
        return results
    
    def split_key(self, key):
        length = 8 #the length of each block
        results = []
        k = ""
        for i in range(len(key)):
            k += key[i]
            if (i+1) % length == 0:
                results.append(k)
                k = ""
        # key1 and key2 in 3DES, original key should be 128 bits long, key1 and key2 will be 64 bits long
        return results[:8], results[8:16] 
    
    def ECB_encrypt(self, input, key):
        key1, key2 = self.split_key(key)
        message_blocks = self.split(input)
        ciphertext = ""
        #Encryption, Decryption, and Encryption (EDE) with 2 different keys.
        #Suppose to be m_n --> c_n --> d_n --> e_n
        for i, m in enumerate(message_blocks):
            c = int(m,2) ^ int(key1[i % 8],2)
            c = c ^ int(key2[i % 8],2)
            c = c ^ int(key1[i % 8],2)
            ciphertext += "{:08b}".format(c)
        return ciphertext

    def ECB_decrypt(self, input, key): 
        pass # will be same as ECB_encrypt since I only use xor here

    def CBC_encrypt(self, input, key):
        key1, key2 = self.split_key(key)
        message_blocks = self.split(input)
        ciphertext = ""
        c_previous1 = int(self.IV,2) 
        c_previous2 = int(self.IV,2) 
        c_previous3 = int(self.IV,2) 
        #Encryption, Decryption, and Encryption (EDE) with 2 different keys.
        #Suppose to be m_n --> c_n --> d_n --> e_n
        for i, m in enumerate(message_blocks):
            #encrypt: c_n = m_n xor key1_n xor c_n-1 
            c = int(m,2) ^ int(key1[i % 8],2) ^ c_previous1 
            c_previous1 = deepcopy(c)

            #encrypt is:  d_n = c_n xor key2_n xor d_n-1 
            #so decrypt should be:  c_n = d_n xor key2_n xor d_n-1 
            x = deepcopy(c)  
            c = x ^ int(key2[i % 8],2) ^ c_previous2 
            c_previous2 = deepcopy(x)

            #encrypt: e_n = d_n xor key1_n xor e_n-1 
            c = c ^ int(key1[i % 8],2) ^ c_previous3 #e_n = d_n xor key1_n xor e_n-1 
            c_previous3 = deepcopy(c)

            ciphertext += "{:08b}".format(c)
        return ciphertext
    
    def CBC_decrypt(self, input, key):
        key1, key2 = self.split_key(key)
        message_blocks = self.split(input)
        ciphertext = ""
        c_previous1 = int(self.IV,2)
        c_previous2 = int(self.IV,2)
        c_previous3 = int(self.IV,2)
        #Decryption, Encryption, and Decryption (DED) with 2 different keys.
        #Suppose to be e_n --> d_n --> c_n --> m_n
        for i, m in enumerate(message_blocks):
            #decrypt: d_n = e_n xor key1_n xor e_n-1 
            x = int(m,2)  #e_n-1 
            c = x ^ int(key1[i % 8],2) ^ c_previous1  
            c_previous1 = deepcopy(x)

            #encrypt:  d_n = c_n xor key2_n xor d_n-1 
            c = c ^ int(key2[i % 8],2) ^ c_previous2 
            c_previous2 = deepcopy(c)

            #decrypt: m_n = c_n xor key1_n xor c_n-1 
            x = deepcopy(c)  #c_n-1 
            c = x ^ int(key1[i % 8],2) ^ c_previous3  #m_n = c_n xor key1_n xor c_n-1 
            c_previous3 = deepcopy(x)

            ciphertext += "{:08b}".format(c)
        return ciphertext