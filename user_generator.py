import random
import hashlib
import json

def salt_generator(length):
    characters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    salt = ''
    for i in range(0, length):
        salt+=(random.choice(characters))
    return salt

def user_generator():
    salt_0 = salt_generator(16)
    salt_1 = salt_generator(16)
    salt_2 = salt_generator(16)
    admin_pass = hashlib.sha256(b'adminpass' + salt_0.encode())
    user1_pass = hashlib.sha256(b'user1pass' + salt_1.encode())
    user2_pass = hashlib.sha256(b'user2pass' + salt_2.encode())
    users = {
        0 : {'username': 'admin', 'password': admin_pass.hexdigest(), 'salt': salt_0, 'group': 'admin',
        'metadata':{
            'friends':[''],
            'group':'admin'
        }},
        1 : {'username': 'user1', 'password': user1_pass.hexdigest(), 'salt': salt_1, 'group': 'regular',
        'metadata': {
            'friends':['user2'],
            'group':'regular'
        }},
        2 : {'username': 'user2', 'password': user2_pass.hexdigest(), 'salt': salt_2, 'group': 'regular',
        'metadata': {
            'friends':['user1'],
            'group':'regular'
        }}
    }
    with open('users_data.json', 'w+') as outfile:
        json.dump(users, outfile)

user_generator()