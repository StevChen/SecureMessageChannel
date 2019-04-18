import sys
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
DEBUG = False

connected_user_count = 0
connected_user_dict = dict()
connected_user_list = list()

def getUsers():
    # this is a function to get user data from the source, either database, file or something
    # For this project, for convenience, since there is only two clients need for demonstration, 
    # so I make up their data in run time
    user1_pass = hashlib.sha256(b'user1pass')
    user2_pass = hashlib.sha256(b'user2pass')
    users = {
        1 : {'username': 'user1', 'password': user1_pass.hexdigest(), 
        'metadata': {
            'friends':['user2']    
        }},
        2 : {'username': 'user2', 'password': user2_pass.hexdigest(), 
        'metadata': {
            'friends':['user1']
        }}
    }
    return users

def verify_username(username : str):
    users = getUsers()
    for user in users:
        # print(users[user]['username'])
        # print(username.decode())
        if(users[user]['username'] == username):
            return users[user]
    return False

# def verify_password(username:str, password:str):
#     users = getUsers()
#     for user in users:
#         if(users[user]['username'] == username and users[user]['password'] == password):
#             return True
#     return False


def on_connection_success(conn, addr):
    global connected_user_count
    global connected_user_dict
    global connected_user_list
    # ========================================================
    # wait for the username and password
    # Echo message b'None if info is incorrect or not found
    # --------------------------------------------------------
    # username
    username = conn.recv(1024)
    user_data = verify_username(username.decode())
    
    if(DEBUG):
        print(user_data)

    if(not user_data):
        print("username not found, client disconnected")
        conn.send(b"None")
        conn.close()
        return
    conn.send(b"success") #replace success with salt if implementing salt
    print("user: ", username.decode(), " connected")

    # ---------------------------------------------------------
    # password
    print("waiting for password...")
    password = conn.recv(1024)
    if(password.decode() != user_data['password']):
        print("invalid password, client disconnected")
        conn.send(b'None')
        conn.close()
        return
    conn.send(b'success')
    print("user: ", username.decode() , " login successfully")
    # ========================================================
    # setup the initial message for user
    connected_user_list.insert(len(connected_user_list), username.decode())
    connected_user = {'username':username.decode(), 'socket':conn, 'addr':addr}
    connected_user_count+=1
    connected_user_dict[connected_user_count] = connected_user

    initial_message = "Thank you for using the secure chat\
                    \nPleas pick one of the options below, eg. '0' for exit \
                    \n [1] Show connected user list\
                    \n [2] Show friend list\
                    \n [3] Chat with friend\
                    \n [0] Disconnect from the server\
                    \nPlease enter your request (without brackets)"

    metadata = user_data['metadata']
    packet = json.dumps({'msg':initial_message, 'metadata':metadata})
    conn.send(packet.encode())


    while(True):
        try:
            request = conn.recv(1024)
            if(request.decode() == '0'):
                conn.send(request)
                try:
                    connected_user_list.remove(username.decode())
                except Exception as e:
                    print('remove user: {} form connected_user_list error: {}'.format(username.decode(), e))
                    sys.exit()

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
        thread = threading.Thread(target=on_connection_success, args=(conn, clientAddr))
        thread.start()
    
    bindsocket.close()

if __name__ == "__main__":
    main()