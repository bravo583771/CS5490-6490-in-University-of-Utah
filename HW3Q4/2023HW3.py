class server(object): #Bob
    def __init__(self, g= 1907, p= 784313, S= 12077):
        self.g = g
        self.p = p
        self.S = S
    
    def send(self,):
        T = self.g**self.S % self.p #TB = g**SB % p
        print("Server sends TB = g^SB mod p = {}".format(T))
        return T
    
    def receive(self, T):
        shared_key = T**self.S % self.p 
        print("Server receives TA = {}".format(T))
        print("TA ^ SB mod p = {} which is equal to g^SASB mod p.".format(shared_key))
        return

class client(object): #Alice
    def __init__(self, g= 1907, p= 784313, S= 160031):
        self.g = g
        self.p = p
        self.S = S

    def send(self,):
        T = self.g**self.S % self.p #TA = g**SA % p
        print("Client sends TA = g^SA mod p = {}".format(T))
        return T
    
    def receive(self, T):
        shared_key = T**self.S % self.p 
        print("Client receives TA = {}".format(T))
        print("TB ^ SA mod p = {} which is equal to g^SASB mod p.".format(shared_key))
        return

def main():
    print("TCP: server open ---> connect with client ---> client sends message to server \n\
            ---> server receives and sends back another messages \n\
            ---> client receives and close (send close to server)\n\
            ---> server close.")
    g = 1907
    p = 784313
    SA = 160031
    SB = 12077
    print("Create server (Bob) with g= {}, p= {}, SB= {}.".format(g, p ,SB))
    Bob = server(g= g, p= p, S= SB)
    print("Create client (Alice) with g= {}, p= {}, SA= {}.".format(g, p ,SA))
    Alice = client(g= g, p= p, S= SA)
    print("")
    TA = Alice.send()
    Bob.receive(TA)
    print("")
    TB = Bob.send()
    Alice.receive(TB)
    print("close server.")
    

#if __name__ == "__main__":
#    main()
main()