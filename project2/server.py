import socket
import time
import base64
from math import ceil
from util import nonceGenerator, encrypt, pad, get_hash, signature, verify, generate_keys, create_certificate, verify_certificate, get_publickey, get_privatekey, get_master_secret, get_hmac
from OpenSSL import crypto
from Crypto.Cipher import PKCS1_OAEP
from struct import pack

def send_file(file, encrypt_key, signature_key, socket):
    print("Sending file, bytes: {}\n".format(len(file)))
    # split the bytes of the file into an array, each element has size 4096
    array_length = ceil(len(file) / 16384)
    print("split the file into the {} length array.".format(array_length))
    socket.send(str(array_length).encode())
    if 'go ahead'== socket.recv(1024).decode():
        print("Alice prepared to receive file. (sequence 0)")
    files_array = []
    for q in range(array_length):
        if q == array_length-1:
            files_array.append(file[q*16384:])
        else:
            files_array.append(file[q*16384:(q+1)*16384])

    #sequence_number, record_header, data, HMAC(digest of the previous three parts), padding
    msg = b"" 
    for i, file_block in enumerate(files_array):
        msg = process_data(file_block, i, encrypt_key, signature_key) #msg should be block1, block2, ...
        socket.send(msg)
        if 'go ahead'== socket.recv(1024).decode():
            print("Alice prepared to receive the next part. (sequence {})".format(i+1))

def process_data(file_block, sequence_num, encrypt_key, signature_key):
    #return an SSL package
    data_len = len(base64.encodebytes(file_block))
    data_len_bin = pack("h", data_len) #2-byte short int 
    padding_len = (8 - (data_len % 8)) % 8 # 8 - 0 = 8, we need (8 - 0) % 8, each block of CBC is 8 bits long
    padding_len_bin = pack("h", padding_len)
    padding_text = '0' * padding_len #string
    record_header = data_len_bin + padding_len_bin
    hmac = get_hmac(sequence_num, record_header, file_block, signature_key) #hexstring
    #data_block = base64.encodebytes(file_block).decode() + hmac + padding_text
    print("The hmac is \n{}".format(hmac))
    data_block = base64.encodebytes(file_block) + hmac.encode() + padding_text.encode()
    ciphertext = encrypt(data_block, encrypt_key)
    return record_header + ciphertext

#This is Bob
if __name__ == "__main__":
    print("Here is Bob's server.")
    my_soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    while True:
        print("\t Please enter 'quit' to exit")
        print("\t Please enter 'wait' to wait for a connection")

        message = input("Enter here -> :")

        if message == 'quit':
            break
        if message == 'wait':
            host = "127.0.0.1"
            port = 8887 
            print("Socket created")
            my_soc.bind((host, port))
            print("Waiting for connection.....")
            my_soc.listen(10) 
            print("Socket is now listening.....")
            #getting the user's connection info
            conn, addr = my_soc.accept()
            ip, port = str(addr[0]), str(addr[1])
            print ("Connection from: ip = {} on port = {}".format(ip, port))
            package = conn.recv(2048)
            msg_hash = get_hash(package, method = "SHA1")
            # receive encryption|integrity_protection|certificate from client
            # find the locations of the '|' 
            msg = package.split('|'.encode())
            encryption = msg[0].decode()
            integrity_protection = msg[1].decode()
            certificate = crypto.load_certificate(crypto.FILETYPE_PEM, msg[2])
            if verify_certificate(certificate, 'Alice'):
                print("Identity verified: Alice")
                print("encrypt: {}, itegrety protect: {}".format(encryption, integrity_protection))
                print("Now generate a nonce R_Bob and send it with Bob's certificate to the client.")
                #Now send R_Bob|certificate to the client 
                RB = nonceGenerator(64)
                Alice_key = get_publickey(certificate, "Alice_public_key.pem")
                encryptor = PKCS1_OAEP.new(Alice_key)
                encrypt_RB = encryptor.encrypt(RB.encode())

                key_pair, certificate = create_certificate("Bob")
                my_privatekey = get_privatekey(key_pair)
                certificate_bytes = crypto.dump_certificate(crypto.FILETYPE_PEM, certificate)
                split = "|".encode()
                msg = encrypt_RB + split + certificate_bytes #len: 256 +1 + 948
                msg_hash += get_hash(msg, method = "SHA1")
                conn.send(msg)
            else:
                print("Invalid certification")
                print("Send invalid to client")
                split = "|".encode()
                msg = pad("invalid", 256) + split + pad(b"", 948)
                conn.send(msg)
                continue
            
            package = conn.recv(2048)
            msg_hash += get_hash(package, method = "SHA1")
            if "invalid".encode() in package:
                print("Fail to certificate my identity")
                continue

            print("receive K_B\{R_Alice|s\} from the Alice")
            decryptor = PKCS1_OAEP.new(my_privatekey)
            msg = decryptor.decrypt(package).split('|'.encode())
            RA = msg[0].decode()
            s = msg[1].decode()
            print("Now we have R_A = {}, R_B = {}, and s = {}".format(int(RA,2), int(RB,2), int(s,2)))

            # Get a master secret from s and two nonces
            master_secret = get_master_secret(s, RA, RB)
            print("Got master secret:", master_secret, "\n")
            Bob_encrypt_key, Bob_sign_key, Alice_encrypt_key, Alice_sign_key = generate_keys(master_secret)
            print("4 keys:\n {}\n {}\n {}\n {}".format(Bob_encrypt_key, Bob_sign_key, Alice_encrypt_key, Alice_sign_key))

            print("Now exchange the sha-1 hashes of the messages.")
            print("Send the hash to Alice")
            send_hash = msg_hash + get_hash("SERVER", method = "SHA1")
            conn.send(send_hash.encode())
            print("Receive the hash from Alice")
            Alice_hash = conn.recv(4096).decode()
            print_hash = input("Print the hash or not? y/n -> ")
            if print_hash == 'y' or print_hash == 'Y':
                print("\nAlice's hash:\n {}\n\nmy hash::\n {}".format(Alice_hash, send_hash))
            if Alice_hash == msg_hash + get_hash("CLIENT", method = "SHA1"):
                print("Verified, the same hash.")
            else:
                print("Invalid, bad hash")
                continue

            transfer_file = input("Transfer a file now? y/n -> ")
            f = open("2023PA2.pdf", "rb")
            file = f.read()
            if transfer_file == 'y' or transfer_file == 'Y':
                print("Transfer the file: {} to Alice.".format(""))
                send_file(file, Bob_encrypt_key, Bob_sign_key, conn)
                print("Finished!")

            f.close()
            time.sleep(5)
            print("Finish the connection")
            my_soc.close()
            
    


