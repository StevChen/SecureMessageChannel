import socket
import threading
import ssl
import hashlib
import json

'''
Server:
It intend to building connection between Two client and allow them to communicate through a secure channel

This server will implemented with:
    1. SSL/TLS 
    2. Password/Login Mechanism
    3. PK exchange and encryption

'''

'''
Make the server into class
'''
#enumerate roles = ['admin', 'regular']
connected_user_count = 0
connected_user_dict = dict()
connected_user_list = list()

class ssl_server:
    def __init__(self, ip : str, port: int, server_cert: str, server_key: str, client_certs: str):
        self.ip = ip
        self.port = port
        self.server_cert = server_cert
        self.server_key = server_key
        self.client_certs = client_certs

    def init_ssl_server(self):
        #create context
        self.context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        #context.verify_mode = ssl.CERT_REQUIRED
        self.context.load_cert_chain(certfile=self.server_cert, keyfile=self.server_key)
        #context.load_verify_locations(cafile=client_certs)

        #create socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind((listen_addr, listen_port))    

    def listen(self, n):
        self.sock.listen(n)    

    def start(self):
        while True:
            # Waiting to clients to establish the connection
            print("Waiting for client......")
            clientSocket, clientAddr = bindsocket.accept()
            conn = context.wrap_socket(clientSocket, server_side=True)

            print("connection established for client: {}".format(clientAddr))

            print("strat a new thread to handle client requests")
            thread = threading.Thread(target=on_login_success, args=(conn, clientAddr))
            thread.start()
        
    def handler(self):
        pass
        '''
        global connected_user_count
        global connected_user_dict
        global connected_user_list
        # wait for the username and password
        # Echo message b'None if info is incorrect or not found
        print("waiting for username...")
        username = conn.recv(1024)
        
        index, connected_user = getUser(username)
        #print(connected_user)
        if(connected_user != None):
            conn.send(b"salt")
        else:
            print("username not found")
            conn.send(b"None")
            conn.close()

        print("user: ", connected_user['username'], " connected")
        print("waiting for password...")
        password = conn.recv(1024)
        if(password == connected_user['password'].encode()):
            conn.send(b'success')
        else:
            print("invalid password")
            conn.send(b'None')
            conn.close()

        print("user: ", connected_user['username'], " login successfully")


        # add connected_user to the connected_user_list
        # add connected client to the "connected_client_list", it socket, address, (username and password)?
        connected_user_list.insert(len(connected_user_list), connected_user['username'])
        connected_user['socket'] = conn
        connected_user['addr'] = addr
        connected_user_count+=1
        connected_user_dict[index] = connected_user
        
        #print(connected_user)
        #print(connected_user_list)
        #print(connected_user_count)
        #connected_user_list[1]['socket'].send(b"added user to the user list")

        initial_message = "Thank you for using the secure chat\
                        \n Pleas pick one of the options below, eg. '0' for exit \
                        \n [1] show connected user list\
                        \n [2] .....\
                        \n [0] disconnect from the server\
                        \n Please enter your request without brackets"

        conn.send(initial_message.encode())
        while(True):
            try:
                request = conn.recv(1024)
                if(request.decode() == '0'):
                    conn.send(request)
                    print("user {} {} disconnected".format(connected_user, addr))
                    break
                if(request.decode() == '1'):
                    conn.send(json.dumps(connected_user_list).encode())
            except ConnectionResetError:
                print("connection closed by the remote client")
                break
        conn.close()
        '''

def getUsers():
    # this is a function to get user data from the source, either database, file or something
    # For this project, for convenience, since there is only two clients need for demonstration, 
    # so I make up their data in run time
    user1_pass = hashlib.sha256(b'user1pass')
    user2_pass = hashlib.sha256(b'user2pass')
    users = {
        
        1 : {'username': 'user1', 'password': user1_pass.hexdigest()},
        2 : {'username': 'user2', 'password': user2_pass.hexdigest()}
    }
    return users

def verify_username(username : str):
    users = getUsers()
    for user in users:
        #print(users[user]['username'])
        if(users[user]['username'] == username):
            return True
    return False

def verify_password(username:str, password:str):
    users = getUsers()
    for user in users:
        if(users[user]['username'] == username and users[user]['password'] == password):
            return True
    return False

def on_login_success(conn, addr):
    global connected_user_count
    global connected_user_dict
    global connected_user_list
    # wait for the username and password
    # Echo message b'None if info is incorrect or not found
    print("waiting for username...")
    username = conn.recv(1024)
    
    #connected_user = getUser(username.decode())
    #print(connected_user)
    if(verify_username(username.decode())):
        conn.send(b"salt")
    else:
        print("username not found, client disconnected")
        conn.send(b"None")
        conn.close()
        return

    print("user: ", username.decode(), " connected")
    print("waiting for password...")
    password = conn.recv(1024)

    #verify user password
    if(verify_password(username.decode(), password.decode())):
        conn.send(b'success')
    else:
        print("invalid password, client disconnected")
        conn.send(b'None')
        conn.close()
        return

    print("user: ", username.decode() , " login successfully")


    # add connected_user to the connected_user_list
    # add connected client to the "connected_client_list", it socket, address, (username and password)?
    connected_user_list.insert(len(connected_user_list), username.decode())
    connected_user = {'username':username.decode(), 'socket':conn, 'addr':addr}
    #connected_user['username'] = username.decode()
    #connected_user['socket'] = conn
    #connected_user['addr'] = addr
    connected_user_count+=1
    connected_user_dict[connected_user_count] = connected_user
    
    #print(connected_user)
    #print(connected_user_list)
    #print(connected_user_count)
    #connected_user_list[1]['socket'].send(b"added user to the user list")

    initial_message = "Thank you for using the secure chat\
                    \n Pleas pick one of the options below, eg. '0' for exit \
                    \n [1] show connected user list\
                    \n [2] .....\
                    \n [0] disconnect from the server\
                    \n Please enter your request without brackets"
    
    conn.send(initial_message.encode())
    while(True):
        try:
            request = conn.recv(1024)
            if(request.decode() == '0'):
                conn.send(request)
                connected_user_list.remove(username)
                print("user {} {} disconnected".format(connected_user, addr))
                break
            if(request.decode() == '1'):
                conn.send(json.dumps(connected_user_list).encode())
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
    #context.verify_mode = ssl.CERT_REQUIRED
    context.load_cert_chain(certfile=server_cert, keyfile=server_key)
    #context.load_verify_locations(cafile=client_certs)

    #create socket
    bindsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bindsocket.bind((listen_addr, listen_port))
    bindsocket.listen(5)


    while True:
        # Waiting to clients to establish the connection
        print("Waiting for client......")
        clientSocket, clientAddr = bindsocket.accept()
        conn = context.wrap_socket(clientSocket, server_side=True)

        print("connection established for client: {}".format(clientAddr))

        print("strat a new thread to handle client requests")
        thread = threading.Thread(target=on_login_success, args=(conn, clientAddr))
        thread.start()
    
    bindsocket.close()

if __name__ == "__main__":
    main()