import socket
from util import nonceGenerator, encrption, pad

my_enc = encrption(method = "ECB")
B_key = pad("{:0b}".format(569053), length = 128)
#Bob's shared key is 569053  
K_AB = '11011010001001111111001001001110010110101101100011100101101110101100101111000000101110110111110111110111010010111001011101000000'
T = K_AB + '00000010' # Alice's id is 00000010
ticket = my_enc.encrypt(T, B_key)
N2 = nonceGenerator(64)
message = ticket + my_enc.encrypt(N2, K_AB) 
#Suppose we got this message from Alice

#This is Trudy
if __name__ == "__main__":
    Bob_soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    Bob_host = "127.0.0.1"
    Bob_port = 8886 
    Bob_soc.connect((Bob_host, Bob_port))

    #now send ticket + K_AB\{N2\}
    message = pad(message)
    print("\nsent ticket, K_AB/{N2/} to Bob")
    Bob_soc.send(message.encode())
    
    # we get K_AB{N2-1,N3} from Bob
    print("\ngot K_AB/{N2-1,N3/} from Bob")
    return_message = Bob_soc.recv(1024).decode() #K_AB{N2-1,N3}
    challenge = return_message[64:128] #K_AB{N3}
    new_message = ticket + challenge

    new_session = input("sent ticket, K_AB/{N3/} to Bob's new session?")    
    if new_session == 'Y' or new_session == 'y':
        New_Bob_soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        New_Bob_host = "127.0.0.1"
        New_Bob_port = 8888 
        New_Bob_soc.connect((New_Bob_host, New_Bob_port))

        #now send ticket + K_AB{N3} to new Bob
        new_message = pad(new_message)
        New_Bob_soc.send(new_message.encode())
        print("Send ticket + K_AB/{N3/} to new Bob")
    
        # we got K_AB{N3-1,N4} from Bob
        return_message = New_Bob_soc.recv(1024).decode() #K_AB{N3-1,N4}
        print("\ngot K_AB/{N3-1,N4/} from Bob")

        verify_nonce = return_message[:64] #K_AB{N3-1}
        message = pad(verify_nonce)
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
        print("Quit")
        
