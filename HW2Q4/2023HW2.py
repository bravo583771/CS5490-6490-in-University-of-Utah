import numpy as np

seed = 2023
np.random.seed(seed)

def create_table():
    """
    The ith character uses table[:,i]
    """
    table = np.zeros([256,8], dtype = np.uint8)
    for i in range(8):
        table[:,i] = np.random.choice(np.arange(256), 256, replace = False)
    return table

table = create_table()

def encryption(input, key):
    for r in range(16):
        """
        xor,
        substitution,
        permutation
        """
        xored = [table[ord(a) ^ ord(b), i] for i, (a,b) in enumerate(zip(input, key))]
        xored = np.unpackbits(np.array(xored).reshape([-1,1]), axis = 1)
        #print(xored)
        output = np.insert(xored[:,1:],7,xored[:,0],axis = 1)
        input = output.copy()
        print("The output after round {} encryption: ".format(r+1))
        print([np.binary_repr(i,width=8) for i in np.packbits(input, axis = 1).reshape([-1])])
        input = [chr(i) for i in np.packbits(input, axis = 1).reshape([-1])]
    ciphertext = ""
    for c in np.packbits(output, axis = 1).reshape([-1]):
        ciphertext = ciphertext + chr(c)
    return ciphertext

def decryption(input, key):
    input = np.unpackbits(np.array([ord(a) for a in input], dtype = np.uint8).reshape([-1,1]), axis = 1)
    for r in range(16):
        """
        reverse permutation,
        reverse substitution,
        reverse xor
        """
        output = np.insert(input[:,:7],0,input[:,7],axis = 1)
        output = np.packbits(output, axis = 1).reshape([-1])
        output = [np.argwhere(table[:,i]==a).item() ^ ord(b) for i, (a,b) in enumerate(zip(output, key))]
        output = np.unpackbits(np.array(output, dtype = np.uint8).reshape([-1,1]), axis = 1)
        input = output.copy()
        print("The output after round {} decryption: ".format(r+1))
        print([np.binary_repr(i,width=8) for i in np.packbits(input, axis = 1).reshape([-1])])
    
    plaintext = ""
    for c in np.packbits(output, axis = 1).reshape([-1]):
        plaintext = plaintext + chr(c)
    return plaintext

def main():
    input = "cs6490hw"
    key = "abc01xyz"
    print("input is: {}, and the key is: {}.".format(input, key))
    ciphertext = encryption(input, key)
    print("The encrypted ciphertext is: {}.".format(ciphertext))
    binary_ciphertext = np.unpackbits(np.array([ord(a) for a in input], dtype = np.uint8).reshape([-1,1]), axis = 1)
    binary_ciphertext = [np.binary_repr(i,width=8) for i in np.packbits(binary_ciphertext, axis = 1).reshape([-1])]
    print("and the corresponding binary text is {}\n\n".format(binary_ciphertext))
    plaintext = decryption(ciphertext, key)
    print("The decrypted plaintext is: {}.".format(plaintext))

#if __name__ == "__main__":
#    main()
main()