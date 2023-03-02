import socket
import numpy as np
seed = 1024
np.random.seed(seed)
from threading import Thread
from util import nonceGenerator, encrption, pad

connections = dict() #Store visited clients (8bits ID)
user_Keys = dict() #Store the keys for visited clients
numberOfUsers = 0
host = "127.0.0.1"
port = 8887   # arbitrary port

g = 1907
p = 784313
SK = 100109

#This is the KDC

def needhamSchroeder(package):
    #receiving the contents
    #(A wants B, NB) store as N1|ID_A|ID_B or N1|ID_A|ID_B|NB
    #send back K_A{N1, ID_B, K_AB, Key_B{K_AB||ID_A|| NB} }
    N1 = package[:64] 
    ID_A = package[64:72]
    ID_B = package[72:80]
    cipher_NB = package[80:]

    #Shared keys established by Diffie Helman exchange
    A_key = user_Keys[ID_A] #K_AS
    B_key = user_Keys[ID_B] #K_BS

    K_AB = nonceGenerator(128) # shared key

    if int(cipher_NB,2) ==0:
        #original Needham Schroeder 
        T = K_AB + ID_A #128+8 = 136 bits
    else:
        #expand Needham Schroeder 
        NB = my_enc.decrypt(cipher_NB, B_key)[:64]
        T = K_AB + ID_A + NB #128+8+64 = 200 bits

    ticket = my_enc.encrypt(T, B_key) #136 or 200 bits
    #creating the message
    message = N1 + ID_B + K_AB + ticket #64 + 8 + 128 + (136 or 200) = 336 or 400 bits
    print("K_AB = ", K_AB)
    ciphertext = my_enc.encrypt(message, A_key)

    return pad(ciphertext)

#initial DH exchange with each connected user
def diffieHelman(client):
    user = connections[client.getpeername()]
    print("initial Diffie Hellman Connection with client {}".format(user))
    message = str(user)
    client.send(message.encode()) #tell Alice/Bob her/his id

    #compute T = g^SK mod p
    #send that to the client
    TK = (g**SK) % p
    client.send(str(TK).encode()) 

    #receives the client calculation
    T = int(client.recv(1024).decode('utf8'))
    #compute the shared key S = T^SK mod p
    S = (T**SK) % p
    user_Keys[user] = pad("{:0b}".format(S), length = 128) #store the shared key for each client
    print("The shared key for client {} = {}".format(user , str(S)))

def receive_input(connection):
    client_input = connection.recv(1024)
    decoded_input = client_input.decode("utf8").rstrip()  # decode and strip end of line
    return decoded_input

def client_connection(connection):
    is_active = True
    #as soon as a user connects we initiated DH
    diffieHelman(connection)

    while is_active:
        client_input = connection.recv(1024).decode('utf8')
        print("client input = ", client_input)
        user = connections[connection.getpeername()]
        if "quit" in client_input:
            #connections[connection.getpeername()] = None
            connection.close()
            print("User " + str(user) + " CLOSED their connection \n")
            is_active = False
        elif 'list' in client_input:
            #user wants to see who they can connect to
            print("Hello {},".format(connection.getpeername()))
            if len(connections)==1:
                output = "You are the only user, there is no other user you can connect to."
                connection.send(output.encode())
            else:
                for user in connections:
                    if connections[connection.getpeername()] == None:
                        pass
                    if user != connection.getpeername():
                        output = "{}: {}\n".format(str(connections[user]),str(user) )
                    else:
                        output = "{}: YOU \n".format(str(connections[user]) )
                        output += str(connections[user]) + ": "
                        output += "YOU \n"
                print("output: ",output)
                connection.send(output.encode())
        elif 'connect' in client_input:
            #"connect|......" should be ID_A|ID_B or ID_A|ID_B|K_AB{NB} 
            package = ""
            for text in client_input.split("|")[1:]:
                package += text
            package = pad(package)
            #should be ID_A|ID_B or ID_A|ID_B|K_AB{NB}

            #find the message you want to send to A
            messageToA = needhamSchroeder(package)
            #send to A and now the KDC's job is done
            connection.send(messageToA.encode())
        else:
            print("User " + str(user) + " sent: {}".format(client_input))
            connection.sendall("-".encode())

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

    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)   
    print("Socket created")

    soc.bind((host, port))
    
    soc.listen(5) 
    print("Socket is now listening...")

    # infinite loop-do not reset for every requests
    while True:
        connection, address = soc.accept()
        ip, port = str(address[0]), str(address[1])
        if connection.getpeername() not in connections.keys():
            numberOfUsers += 1
            connections[connection.getpeername()] = "{:0b}".format(numberOfUsers).zfill(8) 
            #assign an unique index for each visiter (8bits ID)
        client_connection(connection)
        #printing which user connected
    soc.close()