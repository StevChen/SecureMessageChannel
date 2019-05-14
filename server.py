import sys
import socket
import threading
import ssl
import hashlib
import json
import random

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
DEBUG = True

connected_user_count = 0
connected_user_dict = dict()
connected_user_list = list()

def getUsers():
    # this is a function to get user data from the source, either database, file or something
    # For this project, for convenience, since there is only two clients need for demonstration, 
    # so I use lcoal file to store the user data
    users_file = open('users_data.json', 'r')
    users = json.load(users_file)
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
    salt = user_data['salt']
    print(salt)
    conn.send(salt.encode()) #replace success with salt if implementing salt
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
    # connected_user_count+=1
    connected_user_dict[username.decode()] = connected_user
    print("Online Users", connected_user_list)
    initial_message_regular = "Thank you for using the secure chat\
                    \nPleas pick one of the options below, eg. '0' for exit \
                    \n [1] Show friend list\
                    \n [2] Chat with friend\
                    \n [3] wait for chat connection\
                    \n [0] Disconnect from the server\
                    \nPlease enter your request (1, 2, 3...without brackets)"

    initial_message_admin = "Welcome admin\
                    \nPleas pick one of the options below, eg. '0' for exit \
                    \n [1] Show connected users\
                    \n [2] add new user (not implemented)\
                    \n [0] Disconnect from the server\
                    \nPlease enter your request (1, 2, 3...without brackets)"

    if(user_data['group'] == 'admin'):
        # admin
        metadata = user_data['metadata']
        packet = json.dumps({'msg':initial_message_admin, 'metadata':metadata})
        conn.send(packet.encode())
        while(True):
            try:
                request = conn.recv(1024)
                try:
                    packet = json.loads(request.decode())
                except:
                    # user disconnected
                    try:
                        connected_user_list.remove(username.decode())
                    except Exception as e:
                        print('remove user: {} form connected_user_list error: {}'.format(username.decode(), e))
                        sys.exit()
                    print("user {} {} disconnected".format(connected_user, addr))
                    break

                if(int(packet['id']) == 1):
                    conn.send(json.dumps(connected_user_list).encode())

                elif(int(packet['id']) == 2):
                    # add new user, not implemented
                    pass
            except ConnectionResetError:
                print("connection closed by the remote client")
                break
    else:
        # regular user
        metadata = user_data['metadata']
        packet = json.dumps({'msg':initial_message_regular, 'metadata':metadata})
        conn.send(packet.encode())

        while(True):
            try:
                packet = conn.recv(1024)
                try:
                    packet = json.loads(packet.decode())
                except:
                    try:
                        connected_user_list.remove(username.decode())
                    except Exception as e:
                        print('remove user: {} form connected_user_list error: {}'.format(username.decode(), e))
                        sys.exit()

                    print("user {} {} disconnected".format(connected_user, addr))
                    break

                if(int(packet['id']) == 2):
                    # print("option 2", packet['id'], packet['user'])
                    user = packet['user']
                    key = packet['key']
                    if(user in connected_user_list):
                        target_user = connected_user_dict[user]
                        target_user_socket = target_user['socket']
                        # print(type(key))
                        packet = {'user': username.decode(), 'key': key}
                        packet = json.dumps(packet)
                        target_user_socket.send(packet.encode())
                        message_packet = conn.recv(1024)
                        # print('received message ', message_packet)
                        # packet = {'user': username.decode(), 'msg': message.decode()}
                        # packet = json.dumps(packet)
                        target_user_socket.send(message_packet)
                        
                    else:
                        packet = {'id': 9, 'message' : 'user is not connected'}
                        packet = json.dumps(packet)
                        conn.send(packet.encode())
                        
                elif(int(packet['id']) == 3):
                    # print('return message')
                    user = packet['user']
                    key = packet['key']
                    target_user = connected_user_dict[user]
                    target_user_socket = target_user['socket']
                    target_user_socket.send(json.dumps(packet).encode())
            except ConnectionResetError:
                print("connection closed by the remote client")
                break
    conn.close()



def main():

    listen_addr = '127.0.0.1'
    listen_port = 8083
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
    
    # bindsocket.close()
    # print(getUsers())

if __name__ == "__main__":
    main()