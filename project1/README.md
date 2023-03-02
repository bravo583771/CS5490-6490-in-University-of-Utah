# This is python scripts for programming assignment 1.  

1. `util.py` is the scipt for some help functions and classes.  
3DES-CDC and 3DES-ECB are defined in the class `encrption`.  
nonce generator is also defined in this function.  
2. `KDC.py` is the scipt for the KDC  
3. `server.py` is the scipt for Bob  
4. `client.py` is the scipt for Alice  
5. `Trudy.py` is the scipt for Alice   

# libraries and software versions:  
python == 3.9.16  
numpy == 1.23.5  
sockets == 1.0.0  

# To do the original Needham Schroeder protocal:  
Steps:  
1. open a terminal and enter `python3 KDC.py`, then enter `ECB` or `CBC` to choose the encryption method.  
2. open another terminal and enter `python3 server.py`, then enter `ECB` or `CBC` to choose the encryption method. (need to be same as KDC)   
3. stay in the `server.py` terminal and enter `wait` to wait for a visiter, then choose `N` or `n` when the terminal ask if using the expanded Needham Schroeder protocal.   
4. open another terminal and enter `python3 client.py`, then enter `ECB` or `CBC` to choose the encryption method. (need to be same as KDC and server)  
5. stay in the `client.py` terminal and choose `N` or `n` when the terminal ask if using the expanded Needham Schroeder protocal.   
6. Alice input message to Bob after authentication.  

# To do the expanded Needham Schroeder protocal:  
Steps:  
1. open a terminal and enter `python3 KDC.py`, then enter `ECB` or `CBC` to choose the encryption method.  
2. open another terminal and enter `python3 server.py`, then enter `ECB` or `CBC` to choose the encryption method. (need to be same as KDC)   
3. stay in the `server.py` terminal and enter `wait` to wait for a visiter, then choose `Y` or `y` when the terminal ask if using the expanded Needham Schroeder protocal.   
4. open another terminal and enter `python3 client.py`, then enter `ECB` or `CBC` to choose the encryption method. (need to be same as KDC and server)  
5. stay in the `client.py` terminal and choose `Y` or `y` when the terminal ask if using the expanded Needham Schroeder protocal.   
6. Alice input message to Bob after authentication.   

# To do the reflection attack:   
Steps:   
1. open a terminal and enter `python3 KDC.py`, then enter `ECB` to choose the encryption method.   
2. open another terminal and enter `python3 server.py`, then enter `ECB` to choose the encryption method.     
3. stay in the `server.py` terminal and enter `wait` to wait for a visiter, then choose `N` or `n` when the terminal ask if using the expanded Needham Schroeder protocal.    
4. open another terminal and enter `python3 new_server.py`.    
(To simulate different session that Bob opens to listen to different visiter. In real system, the server do this without executing two different scipt.)   
5. open another terminal and enter `python3 Trudy.py`, then enter `Y` or `y` to open a new session with Bob.  
  