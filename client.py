import getpass
import re
import socket
import ssl
import sys
import json


def getUsername(msg = None):
    pattern = '^[a-zA-Z]\w{2,8}$'
    while(True):
        username = input(msg)
        #check the input is in the right pattern, match using the regex
        if(re.match(pattern, username) != None):
            return username
        print("Invalid Username")


def getPassword():
    return getpass.getpass()


def main():

    host_addr = '127.0.0.1'
    host_port = 8082
    server_sni_hostname = 'localPyserver.com'
    server_cert = 'server.crt'
    client_cert = 'client.crt'
    client_key = 'client.key'

    #create ssl context
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=server_cert)
    context.load_cert_chain(certfile=client_cert, keyfile=client_key)

    #create socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    #wrap socket with ssl context
    sslsock = context.wrap_socket(sock, server_side=False, server_hostname=server_sni_hostname)

    #trying to connect to the server
    try:
        sslsock.connect((host_addr, host_port))
    except Exception as e:
        print("connection fail: ", e)
        sys.exit()

    #Ask user for username and password to connect to the server
    
    #username = getUsername("Username: ")
    #password = getPassword()

    #msg = '''
    #{{
    #    "username": {username},
    #    "password": {password}
    #}}
    #'''.format(username=username, password=password)
    
    msg = input("msg")
    
    print("Sending: ", msg)
    sslsock.send(msg.encode())
    data = sslsock.recv(4096)
    print(data)
    print("Closing connection")
    sslsock.close()

if __name__ == "__main__":
    main()