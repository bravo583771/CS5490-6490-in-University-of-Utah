# This is python scripts for programming assignment 2.  

1. `util.py` is the scipt for some functions including `nonceGenerator`, `encrypt`, `pad`, `get_hash`, `generate_keys`, `create_certificate`, `verify_certificate`, `get_publickey`, `get_privatekey`, `get_master_secret`, `get_hmac`.     
2. `server.py` is the scipt for Bob  
3. `client.py` is the scipt for Alice  
 

# libraries and software versions:  
`python` == 3.9.16   
`hashlib`, `random`, `socket`, `time`, `filecmp`, `base64`, `datetime`, and `struct` are included in `python 3.9.16`.  
`numpy` == 1.23.5   
`sockets` == 1.0.0   
`OpenSSL` == 22.0.0    
`Crypto` == 3.17     

# Run the code:
1. first run the server by: `python3 server.py`.    
2. then run the client by: `python3 client.py`.    
  