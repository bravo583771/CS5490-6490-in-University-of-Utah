import socket
from util import nonceGenerator, encrption, pad

#This is Bob
class server(object):
    def __init__(self, ) -> None:
        self.g = 1907
        self.p = 784313
        self.SB = 12077 # the private key

    def diffieHelman(self, kdc):
        #note b is the private key
        #receive public G and P from server
        message = kdc.recv(1024).decode('utf8')
        self.id = message   
        print("My id is {}".format(self.id))     

        #receives T = g^SK mod p
        T = int(kdc.recv(1024).decode('utf8'))

        #compute the shared key S = T^SB mod p
        S = (T**self.SB) % self.p
        self.key_kdc = pad("{:0b}".format(S), length = 128)

        #send T = g^SB mod p to kdc
        TB = (self.g**self.SB) % self.p
        kdc.send(str(TB).encode())
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
    print("Here is Bob, now I am going to do DH exchange with the kdc.")
    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    kdc_host = "127.0.0.1"
    kdc_port = 8887 

    soc.connect((kdc_host, kdc_port))

    Bob = server() 
    #establish the session key with the KDC
    Bob.diffieHelman(soc)
    soc.send("quit".encode()) # to end up the connection with KDC

    while True:
        print("\t Please enter 'quit' to exit")
        print("\t Please enter 'wait' to wait for a connection")

        message = input("Enter here -> :")
        if message == "quit":
            break
        if message == 'wait':
            host = "127.0.0.1"
            port = 8886   # arbitrary port

            expand_NS = input("expanded Needham Schroeder (Y means expanded, N means original)-> (Y or N):")
            my_soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  
            print("Socket created")

            my_soc.bind((host, port))
            print("Waiting for connection.....")
            my_soc.listen(5) 
            print("Socket is now listening...")
            #getting the user's connection info
            conn, addr = my_soc.accept()
            ip, port = str(addr[0]), str(addr[1])
            print ("Connection from: ip = {} on port = {}".format(ip, port))
            package = conn.recv(1024).decode()

            if expand_NS == 'Y' or expand_NS == 'y':
                #receive the contents
                #(A wants B) store as ID_A|ID_B
                ID_A = package[:8]
                ID_B = package[8:16]
                if ID_B != Bob.id:
                    print("not my id.")
                    continue
                print("Alice want Bob, send her K_B/{NB/}")
                #send back K_B{NB}
                NB = nonceGenerator(64)
                ciphertext = my_enc.encrypt(NB, Bob.key_kdc)
                ciphertext = pad(ciphertext) #64 bit
                conn.send(ciphertext.encode())
                # Here Alice has connected with the KDC and sent us:
                # Key_B{K_AB||ID_A|| NB}, K_AB{N2} 128+8+64+64 = 264
                package = conn.recv(1024).decode()

                #ticket is Key_B{K_AB||ID_A|| NB}
                ticket = my_enc.decrypt(package[:200], Bob.key_kdc)
                K_AB = ticket[:128]
                rec_ID_A = ticket[128:136]
                rec_NB = ticket[136:200]
                if rec_NB != NB:
                    print("incorrect nonce")
                    continue
                N2 = my_enc.decrypt(package[200:264], K_AB)
            elif expand_NS == 'N' or expand_NS == 'n':
                #receive the contents
                # Here Alice has connected with the KDC and sent us:
                # Key_B{K_AB||ID_A}, K_AB{N2} 128+8+64 = 200
                
                #ticket is Key_B{K_AB||ID_A} 128+8 = 136
                print("Got ticket = Key_B{K_AB||ID_A} and K_AB{N2} from Alice")
                plaintext = my_enc.decrypt(package[:136], Bob.key_kdc)
                ticket = plaintext[:136]
                K_AB = ticket[:128]
                rec_ID_A = ticket[128:136]
                N2 = my_enc.decrypt(package[136:200], K_AB)
            
            print("\ngot ticket, K_AB/{N2/} from Alice")
            N3 = nonceGenerator(64)
            message = my_enc.encrypt("{:064b}".format(int(N2, 2)-1) + N3, K_AB)
            message = pad(message)
            #now we send back K_AB{N2-1,N3}
            print("send K_AB/{N2-1,N3/} to Alice")
            conn.send(message.encode())

            return_message = conn.recv(1024).decode() #K_AB{N3-1}
            # we got K_AB{N3-1} from Alice
            print("\ngot K_AB/{N3-1/} from Alice")
            challenge = my_enc.decrypt(return_message, K_AB)[:64]

            #if the difference is what we expect (pre-determined), then....
            #we now have a secure encrypted communication!
            if int(challenge,2) == int(N3,2) - 1:
                print("VERIFIED")
                conn.send("VERIFIED".encode())
                while True:
                    data = conn.recv(1024).decode()
                    if "quit" in data:
                        print("Alice quit the connection")
                        break
                    print (str(data))
                    message = input("Enter the message you want to send -> :")
                    conn.send(message.encode())
            else:
                print("fail to verify")
                conn.send("FAIL".encode())
                continue

    soc.send(b'--quit--')


