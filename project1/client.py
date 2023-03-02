import socket
from util import nonceGenerator, encrption, pad

#This is Alice
class client(object):
    def __init__(self, ) -> None:
        self.g = 1907
        self.p = 784313
        self.SA = 160031 # the private key

    def diffieHelman(self, kdc):
        #note b is the private key
        #receive public G and P from server
        message = kdc.recv(1024).decode('utf8')
        self.id = message   
        print("My id is {}".format(self.id))     

        #receives T = g^SK mod p
        T = int(kdc.recv(1024).decode('utf8'))

        #compute the shared key S = T^SA mod p
        S = (T**self.SA) % self.p
        self.key_kdc = pad("{:0b}".format(S), length = 128)

        #send T = g^SB mod p to kdc
        TA = (self.g**self.SA) % self.p
        kdc.send(str(TA).encode())
        #would not print the key in real life
        print("Shared key with kdc = {}".format(str(S)))

if __name__ == "__main__":
    while True:
        method = input("'ECB' or 'CBC' -> ")
        if 'ECB' in method and 'CBC' in method:
            print("can only choose one method.")
            continue
        elif 'ECB' in method:
            my_enc = encrption(method = "ECB")
            break
        elif 'CBC' in method:
            my_enc = encrption(method = "CBC")
            break

    expand_NS = input("expanded Needham Schroeder (Y means expanded, N means original)-> (Y or N):")
    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    kdc_host = "127.0.0.1"
    kdc_port = 8887 
    soc.connect((kdc_host, kdc_port))

    #create the key and use it in function call
    Alice = client()
    Alice.diffieHelman(soc)
    soc.send("list".encode())
    soc.recv(1024).decode()
    N1 = nonceGenerator(64)
    N2 = nonceGenerator(64)
    if expand_NS == 'Y' or expand_NS == 'y':
        print("Connect to the server first for the expanded Needham Schroeder protocal.")
        Bob_soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        Bob_host = "127.0.0.1"
        Bob_port = 8886 
        Bob_soc.connect((Bob_host, Bob_port))
        Bob_soc.send("0000001000000001".encode()) # tell Bob "Alice want Bob"
        ciphertext = Bob_soc.recv(1024).decode()[:64] #receiving K_B{NB}
        print("Obtain the cipher K_B/{NB/} from Bob.")
        package = "connect|" + N1 + "0000001000000001" + ciphertext # N1, "Alice want Bob", K_B{NB}, 64+8+8+64 = 144bits

        soc.send(pad(package).encode("utf8")) # send to KDC: N1, "Alice want Bob", K_B{NB}
        # receiving: Key_A{N1 + ID_B + K_AB + ticket}
        # ticket is Key_B{K_AB||ID_A|| NB} here 
        message = my_enc.decrypt(soc.recv(1024).decode(), Alice.key_kdc) 
        rec_N1 = message[:64]
        ID_B = message[64:72]
        K_AB = message[72:200]
        ticket = message[200:400]
        if rec_N1 == N1:
            print("Obtain the K_AB, Bob's ID, and correct N1 from KDC.")
        else:
            print("incorrect N1")
        soc.send("quit".encode()) # to end up the connection with KDC
    elif expand_NS == 'N' or expand_NS == 'n':
        print("You need to get the ticket first for the original Needham Schroeder protocal.")
        package = "connect|" + N1 + "0000001000000001" # N1, "Alice want Bob"  64+8+8 = 80bits
        soc.send(pad(package,length = 152).encode("utf8")) # send to KDC: N1, "Alice want Bob", K_B{NB} where K_B{NB}= 0
        
        # receiving: Key_A{N1 + ID_B + K_AB + ticket}  64 + 8 + 128 + 136
        # ticket is Key_B{K_AB||ID_A}   here 128+8 = 136 bits
        message = my_enc.decrypt(soc.recv(1024).decode(), Alice.key_kdc)
        rec_N1 = message[:64]
        ID_B = message[64:72]
        K_AB = message[72:200]
        ticket = message[200:336]
        if rec_N1 == N1:
            print("Obtain the K_AB, Bob's ID, and correct N1 from KDC.")
        else:
            print("incorrect N1")
        soc.send("quit".encode()) # to end up the connection with KDC
        Bob_soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        Bob_host = "127.0.0.1"
        Bob_port = 8886 
        Bob_soc.connect((Bob_host, Bob_port))

    #now send ticket + K_AB\{N2\}
    message = ticket + my_enc.encrypt(N2, K_AB) 
    message = pad(message)
    print("\nsent ticket, K_AB/{N2/} to Bob")
    Bob_soc.send(message.encode())
    
    # we get K_AB{N2-1,N3} from Bob
    print("\ngot K_AB/{N2-1,N3/} from Bob")
    return_message = Bob_soc.recv(1024).decode() #K_AB{N2-1,N3}
    decrypted_message = my_enc.decrypt(return_message, K_AB)
    verify_nonce = decrypted_message[:64]
    challenge = decrypted_message[64:128]

    if int(verify_nonce,2) == int(N2,2) - 1:
        print("correct N2")
        N3 = int(challenge,2)
        message = my_enc.encrypt("{:064b}".format(N3-1), K_AB)
        message = pad(message)
        print("\nsent K_AB/{N3-1/} to Bob")
        Bob_soc.send(message.encode()) #send K_AB{N3-1} to verify the connection
        verified = Bob_soc.recv(1024).decode()
        if "FAIL" in verified:
            print("FAIL")
        else:
            print("VERIFIED")
            while True:
                message = input("Enter the message you want to send (send 'quit' to finish the connection) -> :")
                if "quit" in message:
                    Bob_soc.send("quit".encode())
                    break
                Bob_soc.send(message.encode())

                data = Bob_soc.recv(1024).decode()
                print (str(data))        
    else:
        print("incorrect N2")
        Bob_soc.send("fail to verify".encode())
        
