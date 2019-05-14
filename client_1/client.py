import socket
import ssl
import sys
import json
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from utility import Debug_Message, getUsername, getPassword

'''
Client:

This client will implemented with:
    1. SSL/TLS 
    2. Password/Login Mechanism
    3. PK exchange and encryption

'''

DEBUG = False

class ssl_client:
    def __init__(self, host_ip, port, server_hostname, server_cert):
        self.host_ip = host_ip
        self.port = port
        self.server_hostname = server_hostname
        self.server_cert = server_cert

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

    # Initilize the client
    client = ssl_client(host_addr, host_port, server_sni_hostname, server_cert)

    # Connect to the server
    try:
        client.init_client()
    except Exception as e:
        print("Error occur on connecting to the server", e)
        client.close()
        sys.exit()

    print("Connection Success")
    # import private and public key
    private_key = RSA.generate(2048)
    public_key = private_key.publickey()
    cipher = public_key.encrypt(b'hello', 2048)
    # print(cipher[0], "result ", private_key.decrypt(bytes.fromhex(cipher[0].hex())))
    # print(private_key, type(private_key))
    # print(public_key, type(private_key))
    
    # private_key_file = open('private.key')
    # public_key_file = open('public.key')
    # private_key = RSA.importKey(private_key_file.read())
    # public_key = RSA.importKey(public_key_file.read())
    # session  = get_random_bytes(16)
    # session_key = public_key.encrypt(session, 32)
    session_key = public_key
    # print(session_key)
    # Send login infomation to the server
    status = client.login()
    if(status):
        debugLog.debug_message("login success")
    
    # After login successs wait for first packet
    packet = client.wait_for_msg()
    packet = json.loads(packet)
    metadata = packet['metadata']
    print(packet['msg'])
    if(metadata['group'] == 'admin'):
        while(True):
            try:
                request = input("Enter your request: ")
                if(request == '0'):
                    break
                elif(request == '1'):
                    packet = {'id': 1, 'request':'get connected users list'}
                    msg = client.send_and_wait_for_msg(json.dumps(packet).encode())
                    print(msg.decode())
                else:
                    print('unknown request, the request id may not implemented')
            except Exception as e:
                print("Error occured", e)
                break
    else:
        while(True):
            try:
                request = input("Enter your request: ")
                if(request == '0'):
                    break
                elif(request == '1'):
                    print(metadata['friends'])
                elif(request == '2'):
                    print(metadata['friends'])
                    friend = input("Who would you like to chat?")
                    if(friend not in metadata['friends']):
                        print('friend not found')
                    else:
                        packet = {'id': request, 'user' : friend, 'key': session_key.exportKey('PEM').decode()}
                        packet = json.dumps(packet)
                        # print('send my key ', packet)
                        if(DEBUG):
                            # print('session key: ', session_key)
                            pass
                        msg = client.send_and_wait_for_msg(packet.encode())
                        packet = json.loads(msg.decode())
                        if(int(packet['id']) == 9):
                            print(packet['message'])
                        else:
                            # print('received friend key ', packet['key'])
                            # print("return msg", packet)
                            friend_public_key = RSA.importKey(packet['key'])
                            # print(friend_public_key)
                            message = input("Enter your message: ")
                            ciphertext = friend_public_key.encrypt(message.encode(), 256)[0]
                            # print(ciphertext, type(ciphertext))
                            ciphertext = ciphertext.hex()
                            message_packet = {'id': request, 'user':friend, 'msg': ciphertext}
                            message_packet = json.dumps(message_packet)
                            # print('message packet', message_packet)
                            print('sent message')
                            client.send_message(message_packet.encode())

                        # packet = {'id': }
                        # msg = client.send_and_wait_for_msg()
                elif(request == '3'):
                    # waitting for connection
                    print('waiting for chat connection')
                    msg = client.wait_for_msg()
                    # print('chat connected ', msg)
                    friend_packet = json.loads(msg.decode())
                    return_packet = {'id': request, 'user' : friend_packet['user'], 'key': session_key.exportKey('PEM').decode()}
                    # print('Got friend key ', friend_packet['key'])
                    # print('send my key ', return_packet)
                    friend_key = RSA.importKey(friend_packet['key'])
                    # print('return packet ', return_packet)
                    return_packet = json.dumps(return_packet)
                    client.send_message(return_packet.encode())
                    print('waiting for message')
                    message = client.wait_for_msg()
                    message_packet = json.loads(message.decode())
                    # print('received ', message_packet)
                    print('received message')
                    ciphertext = message_packet['msg']
                    # print('ciphertext ', ciphertext, type(ciphertext))
                    # print(ciphertext, type(ciphertext))
                    print('Messsage: ', private_key.decrypt(bytes.fromhex(ciphertext)))
                    print('friend public key(session key): \n', friend_packet['key'])
                    print('ciphertext: ', ciphertext)

                else:
                    print('unknown commend')
            except Exception as e:
                print("Error occured", e)
                break
    print("Closing connection")
    client.close()

if __name__ == "__main__":
    main()