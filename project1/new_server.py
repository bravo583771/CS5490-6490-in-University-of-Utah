import socket
import time

from util import nonceGenerator, encrption, pad

#This is Bob
class server(object):
    def __init__(self, ) -> None:
        self.g = 1907
        self.p = 784313
        self.SB = 12077 # the private key
        self.key_kdc = pad("{:0b}".format(569053), length = 128)

if __name__ == "__main__":
    my_enc = encrption(method = "ECB")
    
    Bob = server() 
    host = "127.0.0.1"
    port = 8888   # arbitrary port

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
    print("Got ticket = Key_B{K_AB||ID_A} and K_AB{N2} from Alice")
    #receive the contents
    # Here Alice has connected with the KDC and sent us:
    # Key_B{K_AB||ID_A}, K_AB{N2} 128+8+64 = 200
            
    #ticket is Key_B{K_AB||ID_A} 128+8 = 136
    plaintext = my_enc.decrypt(package[:136], Bob.key_kdc)
    ticket = plaintext[:136]
    K_AB = ticket[:128]
    rec_ID_A = ticket[128:136]
    N3 = my_enc.decrypt(package[136:200], K_AB)
        
    print("\ngot ticket, K_AB/{N3/} from Alice")
    N4 = nonceGenerator(64)
    message = my_enc.encrypt("{:064b}".format(int(N3, 2)-1) + N4, K_AB)
    message = pad(message)
    #now we send back K_AB{N3-1,N4}
    print("send K_AB/{N3-1,N4/} to Alice")
    conn.send(message.encode())
    time.sleep(5)
    print("time out")