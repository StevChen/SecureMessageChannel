import re
import getpass

class Debug_Message:
    def __init__(self, option = False):
        self.debug = option
    
    def enableDebug(self):
        self.debug = True

    def disableDebug(self):
        self.debug = False
    
    def debug_message(self, str):
        if(self.debug):
            print(str)
        else:
            print("Debug not enable")

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