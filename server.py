# Multi-User Chat Application in Python
# Project by:
# - Guruvansh Singh Bhatia
# - Gaurav Madkaikar

# Server Side

import socket
from threading import Thread
import sys
import time
import json
import datetime
import os

# Load the user database
with open("database/userbase.json") as db:
    userbase = json.load(db)

if len(sys.argv) != 3:
    print("Usage:python <filename> <host> <port>")
    sys.exit(1)

HOST = sys.argv[1]
PORT = int(sys.argv[2])

ADDR = (HOST, PORT)

last_client = None

# Flags
invalid = 0
valid = 1
already_logged_in = 2

# Store usernames corresponding to client socket descriptors
clients = {}
# Store addresses of all connected clients corresponding to their socket descriptors
addresses = {}
# Store all users that are currently logged into the server
user_client = {}

# Sets up handling for incoming clients
def accept_client():
    try:
        while True:
            client, client_address = SERVER.accept()
            response = "%s:%s has connected." % client_address
            # Log the current connection attempt into a log file
            logging(response)
            print(response)

            addresses[client] = client_address
            # Thread 2: Handle each client separately
            Thread(target=handle_client, args=(client, client_address)).start()

    except KeyboardInterrupt:
        response = "\nCaught Keyboard Interrupt while accepting connections"
        logging(response)
        print(response)


# Authenticate the current user with the provided user credentials
def authentication(client, client_address):
    try:
        # Receive username
        username_length = client.recv(4).decode("utf8")
        if not username_length:
            client.close()
            return None, False, None
        username_length = int(username_length)
        logging("<LOGIN>:Username size received")
        username = client.recv(username_length).decode("utf8")
        logging("<LOGIN>:Username received")

        # Receive password
        # Password length is fixed(=64, hashed string) but to maintain uniformity we are accepting it's length
        password_length = client.recv(4).decode("utf8")
        if not password_length:
            client.close()
            return None, False, None
        password_length = int(password_length)
        logging("<LOGIN>:Password size received")
        password = client.recv(password_length).decode("utf8")
        logging("<LOGIN>:Password received")

        # Check for validity of transmission
        if not username:
            logging("<LOGIN>:Invalid Username <%s>. Authetication Failed!" % (username))
            client.close()
            return invalid, True, None
        elif username == "<EXIT>":
            logging("<LOGIN>:Invalid Username <%s>. Authetication Failed!" % (username))
            broadcast_selective(bytes("N", "utf8"), [client], system=True)
            return invalid, True, None

        response = "<LOGIN>:<%s> is attempting to login" % username
        logging(response)
        print(response)
    
        # Check for validity of transmission
        if not password:
            logging("<LOGIN>:Invalid Password for the user <%s>. Authentication Failed!" % (username))
            client.close()
            return invalid, True, None
        elif password == "<EXIT>":
            logging("<LOGIN>:Invalid Password for the user <%s>. Authentication Failed!" % (username))
            broadcast_selective(bytes("N-I", "utf8"), [client], system=True)
            return invalid, True, None

        # Check for existence of username and password in the database
        if username not in userbase or password != userbase[username]:
            response = "<LOGIN>:Invalid Password for the user <%s>. Authentication Failed!" % (username)
            logging(response)
            broadcast_selective(bytes("N-I", "utf8"), [client], system=True)
            print(response)
            return invalid, True, None
        # Check if the user is already online
        if username in user_client:
            response = "<LOGIN>:Attempt for multiple login for user <"+username + "> from client address (%s:%s). Authentication Failed!" % (client_address)
            logging(response)
            print(response)
            broadcast_selective(bytes("N-A", "utf8"), [client], system=True)
            return already_logged_in, True, None

        # Logging for successful authentification at caller function
        return valid, True, username

    except OSError:
        response = "<LOGIN>:OSError Caught at <%s:%s>" % (client_address)
        logging(response)
        return None, False, None


# Register a new user with the provided credentials
def signup(client, client_address):
    global userbase
    try:
        # Receive username
        username_length = client.recv(4).decode('utf-8')
        if not username_length:
            client.close()
            return None, None, False
        username_length = int(username_length)
        logging("<SIGNUP>:Username size received")
        username = client.recv(username_length).decode('utf-8')
        if not username:
            client.close()
            return None, None, False
        logging("<SIGNUP>:Username received")
        # Receive password
        password_length = client.recv(4).decode('utf-8')
        if not password_length:
            client.close()
            return None, None, False
        password_length = int(password_length)

        logging("<SIGNUP>:Password size received")
        password = client.recv(password_length).decode('utf-8')
        if not password:
            client.close()
            return None, None, False
        logging("<SIGNUP>:Password received")
    except:
        response = "<SIGNUP>: SignUp Exception Raised at <%s:%s>" % (
            client_address)
        logging(response)
        print(response)
        return None, False, False

    if username in userbase:
        response = "<SIGNUP>: Username unavailable"
        logging(response)
        return username, False, True
    else:
        userbase[username] = password
        with open("database/userbase.json", "w") as db:
            json.dump(userbase, db)
        # logging done by caller
        return username, True, True

# Handles a single client connection
def handle_client(client, client_address):  
    global last_client, clients, user_client

    try:
        while True:
            # Receive the choice header
            choice_length = client.recv(4).decode('utf-8')
            # If no header received, just return from the thread
            if not choice_length:
                response = "%s:%s has disconnected." % client_address
                logging(response)
                print(response)
                return
            choice_length = int(choice_length)
            logging("<QUERY>: query length received")
            
            # Receive the choice number
            choice = client.recv(choice_length).decode('utf-8')
            logging("<QUERY>: query received")

            # If conditions depending on specific choice
            # Login request
            if choice == "1":
                response = "<QUERY>:Login Request by <%s:%s>" % client_address
                logging(response)
                print(response)
                status, connected, username = authentication(client, client_address)
                if not connected:
                    response = "%s:%s has disconnected." % client_address
                    logging(response)
                    print(response)
                    last_client = None
                    client.close()
                    return
                if status == valid:
                    response = "<LOGIN>:<%s> successfully logged in" % username
                    logging(response)
                    print(response)
                    broadcast_selective(bytes("Y", 'utf-8'),[client], system=True)
                    break
            # Signup request
            elif choice == "2":
                response = "<QUERY>:<%s:%s> requesting user sign-up" % client_address
                logging(response)
                print(response)
                userID, status, connected = signup(client, client_address)
                if not connected:
                    response = "%s:%s has disconnected." % client_address
                    logging(response)
                    print(response)
                    last_client = None
                    client.close()
                    return
                if status:
                    response = "User <" + userID + "> has been registered from <"+str(client_address)+">"
                    logging(response)
                    print(response)
                    broadcast_selective(bytes("Y", 'utf-8'),
                                        [client], system=True)
                else:
                    response = "User <"+userID + "> has been NOT BEEN registered from <" + \
                        str(client_address)+">"
                    logging(response)
                    print(response)
                    broadcast_selective(bytes("N", 'utf-8'), [client], system=True)

            elif choice == "3":
                response = "<QUERY>:%s:%s has disconnected." % client_address
                logging(response)
                print(response)
                last_client = None
                client.close()
                return

            else:
                print(f"CHOICE REQUESTED: {choice}")
                response = "<QUERY>:Invalid Query Requested. Closing Connection by <%s:%s>" % (
                    client_address)
                logging(response)
                print(response)
                broadcast_selective(bytes("<EXIT>", "utf8"), [client])
                last_client = None
                client.close()
                return
    except OSError:
        response = "OSError Caught due to <%s:%s>" % (client_address)
        logging(response)
        response = "%s:%s has disconnected." % client_address
        logging(response)
        print(response)
        last_client = None
        client.close()
        return

    clients[client] = username
    user_client[username] = client

    update_upon_login(client)
    welcome = '**** Welcome ! If you ever want to quit, type <EXIT> to Exit****'
    broadcast_selective(bytes(welcome, "utf8"), [client], system=True)
    msg = f"{username} has joined the chat!"
    broadcast_global(bytes(msg, "utf8"), client_address, system=True)

    try:
        while True:
            msg = ""
            while True:
                msg_len = client.recv(4).decode('utf-8')
                if not msg_len:
                    broadcast_selective(bytes("<EXIT>", "utf8"), [client], system=True)
                    client.close()
                    del user_client[clients[client]]
                    del clients[client]
                    return
                msg_len = int(msg_len)
                msg_sliced = client.recv(msg_len).decode('utf-8')
                if not msg_sliced:
                    broadcast_selective(bytes("<EXIT>", "utf8"), [
                                        client], system=True)
                    client.close()
                    del user_client[clients[client]]
                    del clients[client]
                    return

                # Indicates the end of the message
                if msg_len == 5 and msg_sliced == "<END>" and msg_sliced[:7] != "<START>":
                    break
                msg += msg_sliced[7:]

            msg = bytes(msg, 'utf-8')
            # A valid message
            if msg != bytes("<EXIT>", "utf8"):
                broadcast_global(msg, client_address, "["+username+"]: ")
            # An exit message
            else:
                broadcast_selective(bytes("<EXIT>", "utf8"), [client], system=True)
                last_client = None
                client.close()
                print("<%s> successfully logged out" % (clients[client]))
                print("%s:%s has disconnected." % (client_address))
                del user_client[clients[client]]
                del clients[client]
                broadcast_global(bytes("%s has left the chat." %
                                       username, "utf8"), client_address, system=True)
                break
    except:
        response = "Exception Raised while listening to client (%s:%s)" % (client_address)
        logging(response)
        print(response)

        response = "%s:%s has disconnected." % client_address
        logging(response)
        print(response)

        client.close()
        del user_client[clients[client]]
        del clients[client]
        return

# Broadcast messages globally (i.e. to all clients)
def broadcast_global(original_msg, client_address=None, prefix="", system=False):
    """Broadcasts a message to all the clients."""
    original_msg = original_msg.decode('utf-8')  # Temporary

    global last_client, clients, user_client
    invalid_clients = {}

    # If message sent by same last client do not print his username
    if last_client != prefix:
        original_msg = prefix+original_msg
    # Prepare string to be displayed on the GUI interface
    timestamp = "["+str(datetime.datetime.now().time())[:5]+"]"
    original_msg = original_msg+" "+timestamp
    if original_msg[:-8] != "<EXIT>":
        if system:
            logging("<BROADCAST> By Server")
            chat_backup("<0000>"+original_msg)
            
        else:
            logging("<BROADCAST> By User")
            chat_backup("<0001>"+original_msg)
           
    # Send the message to all clients 
    for client in clients:
        try:
            if system:
                msg = "<SYSTEM>" + original_msg
                msg = ("%04d" % len(msg))+msg
                client.sendall(bytes(msg, "utf8"))
            else:
                for index in range(0, len(original_msg), 1024):
                    msg_slice = original_msg[index:index+1024]
                    msg_slice = "<START>" + msg_slice
                    msg_slice = ("%04d" % len(msg_slice))+msg_slice
                    client.sendall(bytes(msg_slice, "utf8"))
                client.sendall(bytes("0005<END>", "utf8"))

        except BrokenPipeError:
            response = "BrokenPipeError Caught during Broadcasting Globally"
            logging(response)
            print(response)
            invalid_clients[client] = clients[client]
            continue
    # Notify disconnection status to invalid clients (clients who have disconnected)
    for client in invalid_clients:
        last_client = None
        client.close()

        response = "<%s> successfully logged out" % (clients[client])
        logging(response)
        print(response)

        response = "%s:%s has disconnected." % client_address
        logging(response)
        print(response)
        del user_client[clients[client]]
        del clients[client]
        broadcast_global(bytes("%s has left the chat." %
                               invalid_clients[client], "utf8"), system=True)
    last_client = prefix


def broadcast_selective(original_msg, client_list, system=False):
    global last_client, clients, user_client, client_address
    original_msg = original_msg.decode('utf-8')
    invalid_clients = {}
    for index in range(len(client_list)):
        try:
            if system:
                logging("<BROADCAST> Broadcasting Selectively")
                msg = "<SYSTEM>"+original_msg
                msg = ("%04d" % len(msg))+msg
                (client_list[index]).sendall(bytes(msg, 'utf-8'))
            else:
                for index in range(0, len(original_msg), 1024):
                    msg_slice = original_msg[index:index+1024]
                    msg_slice = "<START>" + msg_slice
                    msg_slice = ("%04d" % len(msg_slice))+msg_slice
                    (client_list[index]).sendall(bytes(msg_slice, "utf8"))

                (client_list[index]).sendall(bytes("0005<END>", "utf8"))
        except BrokenPipeError:
            response = "BrokenPipeError Caught during Broadcasting Selectively"
            logging(response)
            print(response)
            invalid_clients[client] = clients[client]
            continue
        except OSError:
            response = "OSError Caught during Broadcasting Globally"
            logging(response)
            print(response)
            invalid_clients[client] = clients[client]
            continue
    # Notify disconnection status to invalid clients (clients who have disconnected)
    for client in invalid_clients:
        last_client = None
        client.close()
        response = "<%s> successfully logged out" % (clients[client])
        logging(response)
        print(response)

        response = "%s:%s has disconnected." % client_address
        logging(response)
        print(response)

        del user_client[clients[client]]
        del clients[client]
        broadcast_global(bytes("%s has left the chat." % invalid_clients[client], "utf8"))

# Load past messages for the current user
def update_upon_login(client):
    response = "Loading Chats for <%s>" % (clients[client])
    logging(response)
    with open("database/backup/chat_backup.txt", "r") as chat_backup:
        lines = chat_backup.read().splitlines()
        for line in lines:
            sender, modified_line = int(line[1:5]), line[6:]
            if sender == 0:
                broadcast_selective(
                    bytes(modified_line, 'utf-8'), [client], system=True)
            if sender == 1:
                broadcast_selective(bytes(modified_line, 'utf-8'), [client])
    return

# Log the current message in the corresponding log file
# Log files are ordered by dates (i.e. new log file for every new day)
def logging(msg):
    date = (str(datetime.date.today())).replace("-", "_")
    try:
        logfile = open("logfiles/log_"+date+".txt", "a")
    except:
        os.makedirs("logfiles")
        logfile = open("logfiles/log_"+date+".txt", "a")
    timestamp = str(datetime.datetime.now().time())
    logfile.write("["+timestamp+"]:"+msg+"\n")
    logfile.close()

# Open chat_backup.txt for storing any new messsages
def chat_backup(msg):
    try:
        backup = open("database/backup/chat_backup.txt", "a")
    except:
        os.makedirs("database")
        backup = open("database/backup/chat_backup.txt", "a")

    backup.write(msg+"\n")
    backup.close()


if __name__ == "__main__":
    try:
        SERVER = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Reuse the port if already in use
        SERVER.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        SERVER.bind(ADDR)
        SERVER.listen(5)
        print("Waiting for connection...")

        # Stop execution of ACCEPT_THREAD as soon as server terminates
        ACCEPT_THREAD = Thread(target=accept_client, daemon=True)
        
        print("----- Enter <EXIT> to exit -----")

        # Thread 1: Accept_Thread
        ACCEPT_THREAD.start()

        while True:
            cmd = input()
            logging("<INPUT>:"+cmd)
            if cmd == "<EXIT>":
                response = "<SYSTEM>:Closing Server. Aborting!"
                logging(response)
                print("<SYSTEM>:Closing Server. Aborting!")
                broadcast_global(bytes("<EXIT>", 'utf-8'), system=True)
                SERVER.close()
                sys.exit(1)
            elif cmd == "<ACTIVE USERS>":
                response = "<SYSTEM>:"+repr(list(user_client.keys()))
                logging(response)
                print(response)
            elif cmd == "<DELETE CHAT BACKUP>":
                if len(user_client) == 0:
                    open("database/backup/chat_backup.txt", "w").close()
                    response = "<SYSTEM>:Data Cleared Successfully"
                    logging(response)
                    print("<SYSTEM>:Data Cleared Successfully")
                else:
                    response = "<SYSTEM>:Chatroom Currently Active"
                    logging(response)
                    print("<SYSTEM>:Chatroom Currently Active")
            else:
                response = "<SYSTEM>:Unknown Command"
                logging(response)
                print(response)
        ACCEPT_THREAD.join()
        SERVER.close()

    except KeyboardInterrupt:
        response = "\n<SYSTEM>:Caught Keyboard Interrupt"
        logging(response)
        print(response)

        for client in clients:
            response = "***** Server Disconnected *****"
            logging(response)
            broadcast_global(bytes("<EXIT>", "utf8"), system=True)

        SERVER.close()
        sys.exit(1)