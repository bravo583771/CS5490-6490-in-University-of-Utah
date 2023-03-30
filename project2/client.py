import socket
import time
import filecmp
import base64
from datetime import datetime
from util import nonceGenerator, decrypt, pad, get_hash, signature, verify, generate_keys, create_certificate, verify_certificate, get_publickey, get_privatekey, get_master_secret, get_hmac
from OpenSSL import crypto
from Crypto.Cipher import PKCS1_OAEP
from struct import unpack

# extract data
def receive_data(client_socket, decrypt_key, signature_key):
    #sequence_num = 0 
    #processed_data = True
    data = b""
    array_size = int(client_socket.recv(1024).decode(),10)
    client_socket.send("go ahead".encode())
    print("tell the server 'go ahead'\n")
    print("Bob splits the file into {} parts.".format(array_size))
    for sequence_num in range(array_size):
        #print("Processing data block, sequence number: {} \n".format(sequence_num))
        received_bytes = client_socket.recv(209600)
        record_header = received_bytes[:4] #record_header of the current first block
        data_len = unpack("h", record_header[:2])[0]
        padding_len = unpack("h", record_header[2:4])[0]
        encrypted_bytes_len = data_len + 64 + padding_len #length of one block data (received_bytes should be block1 + block2 + ...)
        split_file = received_bytes[4:4+encrypted_bytes_len]
        
        #the first block, decrypted_byte = base64.encodebytes(file_block).decode() + hmac + padding_text
        decrypted_byte = decrypt(split_file, decrypt_key)
        #decrypted_str = decrypted_byte.decode()
        file_block = base64.decodebytes(decrypted_byte[:data_len])
        hmac = decrypted_byte[data_len:(data_len + 64)].decode()
        verified_hmac = get_hmac(sequence_num, record_header, file_block, signature_key) #hexstring
        print("The hmac is \n{}\nand the expected hmac is \n{}".format(hmac, verified_hmac))
        if hmac == verified_hmac:
            print("hmac check passed")
        else:
            print("Invalid hmac")
            break
            
        data += file_block
        print("Finished processing, sequence number: {}".format(sequence_num))
        if sequence_num < array_size-1:
            client_socket.send("go ahead".encode())
            print("tell the server 'go ahead'\n")
        elif sequence_num == array_size-1:
            client_socket.send("Finish".encode())
    return data

#This is Alice
if __name__ == "__main__":
    print("Here is Alice's terminal.")
    my_soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    while True:
        print("\t Please enter 'connect' to connect with Bob's server")
        print("\t Please enter 'quit' to quit the terminal")

        message = input("Enter here -> :")
        if message == 'quit':
            break
        if message == 'connect':
            host = "127.0.0.1"
            port = 8887 
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect((host, port))
            split = "|".encode()
            key_pair, certificate = create_certificate("Alice")
            my_privatekey = get_privatekey(key_pair)
            msg = b"3DES-CBC" + split + b"MD5" + split
            certificate_bytes = crypto.dump_certificate(crypto.FILETYPE_PEM, certificate)
            msg += certificate_bytes
            #send encryption|integrity_protection|certificate to server
            print("Send 3DES-CBC|MD5|certificate to the server")
            client_socket.send(msg)
            msg_hash = get_hash(msg, method = "SHA1")
            # receive R_Bob|certificate from server, no negotiate methods here
            package = client_socket.recv(2048)
            msg_hash += get_hash(package, method = "SHA1")
            if "invalid".encode() in package:
                print("Fail to certificate my identity")
                continue
            print("receive R_Bob|certificate from the server")
            RB = package[:256]
            
            certificate = crypto.load_certificate(crypto.FILETYPE_PEM, package[257:1205])

            if verify_certificate(certificate, 'Bob'):
                print("Identity verified: Bob")
                Bob_key = get_publickey(certificate, "Bob_public_key.pem")
                decryptor = PKCS1_OAEP.new(my_privatekey)
                RB = decryptor.decrypt(RB).decode()
                #ast.literal_eval(str(RB))
                RB_Int = int(RB,2)

                print("Now generate a nonce R_Alice and s to Bob (K_B\{R_Alice|s\}).")
                #Now send K_B\{R_Alice|s\} to the server 
                RA = nonceGenerator(64)
                s = nonceGenerator(64)
                msg = RA.encode() + split + s.encode()
                encryptor = PKCS1_OAEP.new(Bob_key)
                encrypt_msg = encryptor.encrypt(msg)
                msg_hash += get_hash(encrypt_msg, method = "SHA1")
                client_socket.send(encrypt_msg)
            else:
                print("Invalid certification")
                print("Send invalid to the server")
                msg = pad("invalid", 256) + split + pad(b"", 948)
                client_socket.send(msg)
                continue

            print("Now we have R_A = {}, R_B = {}, and s = {}".format(int(RA,2), int(RB,2), int(s,2)))

            # Get a master secret from s and two nonces
            master_secret = get_master_secret(s, RA, RB)
            print("Got master secret:", master_secret, "\n")
            Bob_encrypt_key, Bob_sign_key, Alice_encrypt_key, Alice_sign_key = generate_keys(master_secret)
            print("4 keys:\n {}\n {}\n {}\n {}".format(Bob_encrypt_key, Bob_sign_key, Alice_encrypt_key, Alice_sign_key))

            print("Now exchange the sha-1 hashes of the messages.")
            print("Receive the hash from Bob")
            Bob_hash = client_socket.recv(4096).decode()
            print("Send the hash to Bob")
            send_hash = msg_hash + get_hash("CLIENT", method = "SHA1")
            client_socket.send(send_hash.encode())
            print_hash = input("Print the hash or not? y/n -> ")
            if print_hash == 'y' or print_hash == 'Y':
                print("\nBob's hash:\n {}\n\nmy hash::\n {}".format(Bob_hash, send_hash))
            if Bob_hash == msg_hash + get_hash("SERVER", method = "SHA1"):
                print("Verified, the same hash.")
            else:
                print("Invalid, bad hash")
                continue
            
            print("Now waiting for Bob transfer the file.")
            data = receive_data(client_socket, Bob_encrypt_key, Bob_sign_key)
            print("Received data from Bob!\n")

            
            f = open("received_file.pdf", "wb+")
            f.write(data)
            f.close()
            filecmp.clear_cache()
            if filecmp.cmp("2023PA2.pdf", "received_file.pdf"):
                print("received_file is same as 2023PA2.pdf. Successfully received!\n")
            else:
                print("received_file is different from 2023PA2.pdf. Fail to receive!\n\n")
            
            time.sleep(5)
            print("Finish the connection")
