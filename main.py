import socket
import threading
import ssl

'''
This file is main program of the TCP server. It intend to building connection between 
Two client and allow them to communicate through a secure channel

This server will implemented with:
    1. SSL/TLS 
    2. Password/Login Mechanism
    3. PK exchange and encryption

'''



class TCPserver:
    def __init__(self, ip : str, port: int):
        self.ip = ip
        self.port = port

    def getSocket(self):
        pass
    
    def sslSocket(self):
        pass

    
    

def main():

    listen_addr = '127.0.0.1'
    listen_port = 8082
    server_cert = 'server.crt'
    server_key = 'server.key'
    client_certs = 'client.crt'

    #create context
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_cert_chain(certfile=server_cert, keyfile=server_key)
    context.load_verify_locations(cafile=client_certs)

    #create socket
    bindsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bindsocket.bind((listen_addr, listen_port))
    bindsocket.listen(5)

    while True:
        print("Waiting for client.......")
        clientSocket, clientAddr = bindsocket.accept()
        conn = context.wrap_socket(clientSocket, server_side=True)

        print("connection established for client: {}".format(clientAddr))
        
        #waiting user login info
        print("waiting for username and password")
        loginInfo = conn.recv(1024)
        
        #check login info
        print("Login Info", loginInfo)

        #if login info is correct, echo "sucess" msg back to client
        #otherwise, echo "incorrect" msg back to client
        #if atempt exceed 3 times, close the connection
        

        
        
        
        
        
        #if login is sucess, loop and waiting for command
        #close connection is receive msg 'exit()'
        while True:
            data = conn.recv(4096)
            print("Received:", data)
            if(data == b'exit()'):
                break
    
        conn.send(b'Login Sucess')
        conn.shutdown(socket.SHUT_RDWR)
        conn.close()

if __name__ == "__main__":
    main()