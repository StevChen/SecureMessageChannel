import socket
import threading
import ssl
import hashlib

'''
Server:
It intend to building connection between Two client and allow them to communicate through a secure channel

This server will implemented with:
    1. SSL/TLS 
    2. Password/Login Mechanism
    3. PK exchange and encryption

'''


class TCPserver:
    def __init__(self, ip : str, port: int, server_cert: str, server_key: str, client_certs):
        self.ip = ip
        self.port = port

    def ssl_socket():
        pass

    def getSocket(self):
        pass
    
    def sslSocket(self):
        pass

def getUsers():
    # this is a function to get user data from the source, either database, file or something
    # For this project, for cconvenience, since there is only two clients, so their data is make
    # up in run time
    user1_pass = hashlib.sha256(b'user1pass')
    user2_pass = hashlib.sha256(b'user2pass')
    users = {
        1 : {'username': b'user1', 'password': user1_pass.hexdigest().encode()},
        2 : {'username': b'user2', 'password': user2_pass.hexdigest().encode()}
    }
    return users

def getUser(username:bytes):
    users = getUsers()
    for user in users:
        print(users[user]['username'])
        if(users[user]['username'] == username):
            return users[user]
    return None

def on_login_success(conn):
    initial_message = "Welcome to the server, the secure chat......"
    conn.send(initial_message.encode())
    while(True):
        try:
            request = conn.recv(1024)
            if(request.decode() == 'exit'):
                conn.send(request)
                break
        except ConnectionResetError:
            print("connection closed by the remote client")
            break
    conn.close()

def main():
    #hasher = hashlib.sha256()
    #hasher.update(b'admin')
    #hashed_username = hasher.hexdigest()

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
        # Waiting to clients to establish the connection
        print("Waiting for client.......")
        clientSocket, clientAddr = bindsocket.accept()
        conn = context.wrap_socket(clientSocket, server_side=True)

        print("connection established for client: {}".format(clientAddr))
        
        
        # After a client connected, wait for the username and password
        # Echo message b'None if info is incorrect or not found
        print("waiting for username")
        username = conn.recv(1024)
        
        connected_user = getUser(username)
        #print(usernames)
        if(connected_user != None):
            conn.send(b"salt")
        else:
            print("username not found")
            conn.send(b"None")
            conn.close()
            continue

        password = conn.recv(1024)
        if(password == connected_user['password']):
            conn.send(b'success')
        else:
            print("invalid password")
            conn.send(b'None')
            conn.close()
            continue
        
        #if login info is correct, echo "success" msg back to client
        #otherwise, echo "None" back to client
        #if sucess put the process into a new thread
        thread = threading.Thread(target=on_login_success, args=(conn,))
        thread.start()
    
    bindsocket.close()

if __name__ == "__main__":
    main()