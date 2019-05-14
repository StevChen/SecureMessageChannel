import socket
import ssl
import sys
import json
import hashlib
from Crypto.PublicKey import RSA
from utility import Debug_Message, getUsername, getPassword

'''
Client:

This client will implemented with:
    1. SSL/TLS 
    2. Password/Login Mechanism
    3. PK exchange and encryption

'''

DEBUG = True

class ssl_client:
    def __init__(self, host_ip, port, server_hostname, server_cert, client_cert, client_key):
        self.host_ip = host_ip
        self.port = port
        self.server_hostname = server_hostname
        self.server_cert = server_cert
        self.client_cert = client_cert
        self.client_key = client_key

    def verify_message(self, msg:bytes):
        if(msg == b'None'):
            return False
        return True


    def init_client(self):
        # create ssl context
        self.context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=self.server_cert)
        # self.context.load_cert_chain(certfile=self.client_cert, keyfile=self.client_key)

        # create socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
        self.sslsock = self.context.wrap_socket(sock, server_side=False, server_hostname=self.server_hostname)

        try:
            self.sslsock.connect((self.host_ip, self.port))
        except Exception as e:
            print("connection fail: ", e, " client exit.")
            sys.exit()
    
    def send_username(self):
        # get username and send to the server
        username = getUsername("Username: ")
        try:
            self.sslsock.send(username.encode())
        except Exception as e:
            print("fail to send username...")
            sys.exit()
        # waiting to receive salt for password hash
        # return b'None' username is not in the database
        msg = self.sslsock.recv(1024)
        if(self.verify_message(msg)):
            return msg
        # invalid username
        if(DEBUG):
            print("Username not found")
            self.sslsock.close()
            sys.exit()
        return msg


    def send_password(self, salt):
        hasher = hashlib.sha256()
        hasher.update((getPassword() + salt).encode())
        password = hasher.hexdigest()
        # trying to send password
        try:
            self.sslsock.send(password.encode())
        except Exception as e:
            print("fail to send password...")
            sys.exit()
        msg = self.sslsock.recv(1024)
        if(self.verify_message(msg)):
            return msg
        
        # invalid password
        print("Invalid Password")
        self.sslsock.close()
        sys.exit()

    def login(self):
        # send username and possible get the salt
        salt = self.send_username()
        if(DEBUG):
            print('Recevied Salt: ', salt.decode())
        # debugLog.debug_message("send user success")
        # send password
        msg = self.send_password(salt.decode())
        return True
    
    def wait_for_msg(self):
        packet = self.sslsock.recv(1024)
        if(DEBUG):
            print("Got packet ", packet)
        return packet
    
    def send_message(self, msg:bytes):
        self.sslsock.send(msg)
    
    def send_and_wait_for_msg(self, msg:bytes):
        self.sslsock.send(msg)
        return self.sslsock.recv(1024)

    def close(self):
        self.sslsock.shutdown(socket.SHUT_RDWR)
        self.sslsock.close()

def main():
    # initilize debug message object
    debugLog = Debug_Message(True)

    host_addr = '127.0.0.1'
    host_port = 8083
    server_sni_hostname = 'localPyserver.com'
    server_cert = 'server.crt'
    client_cert = 'client.crt'
    client_key = 'client.key'

    # Initilize the client
    client = ssl_client(host_addr, host_port, server_sni_hostname, server_cert, client_cert, client_key)

    # Connect to the server
    try:
        client.init_client()
    except Exception as e:
        print("Error occur on connecting to the server", e)
        client.close()
        sys.exit()

    print("Connection Success")


    # Send login infomation to the server
    status = client.login()
    if(status):
        debugLog.debug_message("login success")
    
    # After login successs wait for first packet
    packet = client.wait_for_msg()
    packet = json.loads(packet)
    metadata = packet['metadata']
    print(packet['msg'])
    while(True):
        try:
            request = input("Enter your request: ")
            if(request == '2'):
                print(metadata['friends'])
            elif(request == '3'):
                print(metadata['friends'])
                friend = input("Who would you like to chat?")
                if(friend not in metadata['friends']):
                    print('friend not found')
                else:
                    print(key)
                    msg = client.send_and_wait_for_msg(request.encode())
                    print(msg)
            else:
                packet = build_pack(request, )
                msg = client.send_and_wait_for_msg(request.encode())
                if(DEBUG):
                    print(msg)
        except Exception as e:
            print("Error occured", e)
            break
    print("Closing connection")
    client.close()

if __name__ == "__main__":
    main()