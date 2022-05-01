# Multi-User Chat Application in Python
# Project by:
# - Guruvansh Singh Bhatia
# - Gaurav Madkaikar

# Client Side

import socket
from threading import Thread
import sys
import time
import hashlib
import tkinter
import getpass
import shutil
import os

# Current active status (Initially)
online = False
# Store the current username
clientname = None

# Instructions to the GUI on receiving a message
def system_instruction(msg, client_socket):
    global online
    if msg == "EXIT":
        quit_GUI(client_socket, top)
        return
    timestamp, msg = msg[-8:], msg[:-8]
    try:
        # Exit the GUI
        if msg == "<EXIT>":
            quit_GUI(client_socket, top)
            return
        # Normal text message to be displayed in the GUI module
        else:
            if len(msg) > 0 and msg[-1] == "*":
                msg_list.insert(tkinter.END, msg)
            else:
                msg_list.insert(tkinter.END, msg+" "+timestamp)
    except RuntimeError:
        return

# Quit the GUI interface
def quit_GUI(client_socket, top=None):
    global online
    if online:
        client_socket.close()
        if top:
            top.quit()
        online = False
        print("\n<Press Enter to Quit>")

# An event is passed by binders in the GUI
# Handles sending of messages
def send_data(event=None):
    global online
    try:
        # Get the typed message and strip any trailing whitespaces
        message = message_sent.get().strip()
        # Clear input field
        message_sent.set("")

        if len(message) == 0:
            return
        # Send messages in chunks
        # Message Length = 1024 bytes
        # Message Format: Header (4 bytes) | Preamble (<START> - 7 bytes) | Data (1013 bytes)
        for index in range(0, len(message), 1013):
            message_slice = "<START>"+message[index:(index+1013)]
            message_slice = f"{len(message_slice):04}" + message_slice
            client_sockfd.sendall(bytes(message_slice, 'utf8'))
        # End of the message body
        client_sockfd.sendall(bytes("0005<END>", 'utf8'))
        if len(message) == 10 and message[4:] == "<EXIT>":
            quit_GUI(client_sockfd, top)

    except KeyboardInterrupt:
        print("\nCaught Keyboard interrupt\n--------- Exitting client ---------\n")
        quit_GUI(client_sockfd, top)
        sys.exit(1)

    except BrokenPipeError:
        print("Broken Pipe Error\n")
        quit_GUI(client_sockfd, top)
        sys.exit(1)

def close_GUI_window(event=None):
    # This function is to be called when the window is closed
    global online
    # If a user is online, send the EXIT command to the server to indicate termination
    if online:
        try:
            message_sent.set("<EXIT>")
            # Send notification to all user clients from the server
            send_data()
            top.quit()
        except:
            print("Exception raised while closing the GUI window!")


def receive_data():
    # Handles receiving of messages
    global online
    while True:
        msg = ""
        system_flag = False
        try:
            while True:
                msg_length = client_sockfd.recv(4).decode('utf-8')
                if not msg_length:
                    quit_GUI(client_sockfd, top)
                    return
                msg_length = int(msg_length)
                msg_slice = client_sockfd.recv(msg_length).decode("utf-8")
                # msg_slice[:-8] = Raw messsage without the timestamp
                if not msg_slice or msg_slice[:-8] == "<EXIT>":
                    quit_GUI(client_sockfd, top)
                    return
                # Any system related command (Abort/Unknown command) mostly errors
                if msg_slice[:8] == "<SYSTEM>":
                    # system message
                    msg += msg_slice[8:]
                    system_flag = True
                    break
                # Exit command
                elif msg_length == 5 and msg_slice == "<END>":
                    break
                else:
                    # normal message
                    msg += msg_slice[7:]

        except OSError:  # Possibly client has left the chat.
            break

        except ValueError:
            quit_GUI(client_sockfd, top)
            break

        except:
            print("Exception Caught while Listening. Exitting")
            quit_GUI(client_sockfd, top)
            break
        # For a system command, broadcast to all clients
        if system_flag:
            system_instruction(msg, client_sockfd)
        else:
            timestamp = msg[-7:]
            msg = msg[:-7]
            # Display only 48 characters at a time and append a "-" at the end
            for index in range(0, len(msg), 48):
                msg_slice = msg[index:index+48]
                if len(msg_slice) == 48 and len(msg)-index > 48 and msg[index+48] != " " and msg[index+47] != " ":
                    msg_slice += "-"
                if index == 0:
                    msg_slice = msg_slice+" "+timestamp
                msg_list.insert(tkinter.END, msg_slice)

def client_signup(client_sockfd):
    global online
    # Signup user with the provided details
    while True:
        username = input("Enter your username(Max 20 characters): ")
        if len(username) > 20:
            print("Invalid username. Please choose a username of length upto 20 characters")
        else:
            break
    while True:
        password = getpass.getpass("Enter your password(Max 32 characters): ")
        if len(password) > 32:
            print("Invalid password. Please choose a password of length upto 32 characters")
            continue
        reenter_password = getpass.getpass("Re-enter your password: ")
        if password == reenter_password:
            hash_password = (hashlib.sha256(password.encode())).hexdigest()
            break
        else:
            print("Passwords don't match. Enter again!")

    try:
        padded_username = f"{len(username):04}" + username
        client_sockfd.sendall(bytes(padded_username, 'utf-8'))

        padded_password = f"{len(hash_password):04}" + hash_password
        client_sockfd.sendall(bytes(padded_password, 'utf-8'))

        status_length = client_sockfd.recv(4).decode('utf-8')
        if not status_length:
            quit_GUI(client_sockfd, top=None)
            sys.exit(1)
        status_length = int(status_length)
        status = client_sockfd.recv(status_length).decode('utf-8')

        if not status or status[:8] != "<SYSTEM>":
            quit_GUI(client_sockfd, top=None)
            sys.exit(1)

    except ConnectionError:
        print("Connection closed. Please reconnect to the server")
        quit_GUI(client_sockfd, top=None)
        sys.exit(1)

    if status[8:] == 'Y':
        return True
    else:
        return False

# If true => user is logged in, else => user not logged in
def client_login(client_sockfd):
    global active, clientname
    username = input("Username: ")
    password = getpass.getpass("Password: ")

    if len(username) > 20 or len(password) > 32:
        print("Invalid user credentials!\n")
        return False
    # Attach header to username and password
    padded_username = f"{len(username):04}" + username
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    padded_password = f"{len(hashed_password):04}" + hashed_password

    try:
        # Send username and encrypted password to the server
        client_sockfd.sendall(bytes(padded_username, 'utf-8'))
        client_sockfd.sendall(bytes(padded_password, 'utf-8'))

        status_code = client_sockfd.recv(4).decode('utf-8')
        if not status_code:
            quit_GUI(client_sockfd, top=None)
            print("Invalid user credentials!\n")
            sys.exit(1)
        status_len = int(status_code)
        status = client_sockfd.recv(status_len).decode('utf-8')

        if not status or status[:8] != "<SYSTEM>":
            quit_GUI(client_sockfd, top=None)
            sys.exit(1)

    except:
        print("Exception raised at login()")
        quit_GUI(client_sockfd, top=None)
        sys.exit(1)
    # Different status codes
    # Succesful logging in
    if status[8:9] == "Y":
        print(f"User <{username}> successfully logged in!")
        clientname = username
        return True
    # User already logged in
    elif status[8:9] == "N" and status[10:11] == "A":
        print(f"<{username}> is currently logged in through another client\nDisconnect it to login on this client!")
        return False
    # Invalid credentials
    else:
        print("Invalid user credentials!")
        return False

# Method launched by the interaction thread for each individual client
def launch_terminal(top, socket):
    global online
    print("Interaction Terminal Activated. Type <EXIT> to log out")
    while True:
        try:
            input_command = input("Input: ")
            if not online:
                return
            if stop_threads == True:
                return
            # Take command for exiting the GUI
            if input_command == "<EXIT>":
                message_sent.set("<EXIT>")
                send_data()
                quit_GUI(client_sockfd, top)
                return
            else:
                print("<SYSTEM>:Unknown Command")
        except:
            print("The server (%s:%s) is not active. Exitting..." % ADDR)
            quit_GUI(socket, top)
            sys.exit(1)

# Main method: Execution starts here
if __name__ == "__main__":
    print("MULTI-USER CHAT APPLICATION")
    print("---------------------------------- Client Side ----------------------------------")

    try:
        HOST = input("Enter host: ")
        PORT = input("Enter port: ")

        # Set a default port if not already set
        if not PORT:
            PORT = 33011
        else:
            PORT = int(PORT)
    # Catch any keyboard interrupts
    except KeyboardInterrupt:
        print("\nCaught Keyboard interrupt\n--------- Exitting client ---------\n")
        sys.exit(1)
    # Catch any invalid port errors
    except ValueError:
        print("Invalid port\n")
        sys.exit(1)

    # Server Address as given by the user
    ADDR = (HOST, PORT)

    # Loop
    while True:
        try:
            # Estabilish a TCP connection
            client_sockfd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_sockfd.connect(ADDR)

            while True:
                print("\n--^-- WELCOME TO THE CHAT APP --^--")

                # Take user choice
                choice = input("1. Chatroom\n2. Signup\n3. Quit\nSelect any one option: ")
                sender_command = f"{len(choice):04}"+choice

                # If conditions for specific choices

                # Chatroom (Login + Instantiate tkinter window for message sharing)
                if choice == "1":
                    client_sockfd.sendall(bytes(sender_command, 'utf-8'))
                    # Check if the client is already logged in if not ask for user credentials
                    if client_login(client_sockfd):
                        break
                    else:
                        continue
                # Signup a new user with username and password
                elif choice == "2":
                    client_sockfd.sendall(bytes(sender_command, 'utf-8'))
                    if client_signup(client_sockfd):
                        print("Successful registration!")
                    else:
                        print("Unsuccessful registration!")
                    continue
                # Close the connection and exit
                elif choice == "3":
                    client_sockfd.sendall(bytes(sender_command, 'utf-8'))
                    client_sockfd.close()
                    sys.exit(1)
                # Invalid choice selected
                else:
                    print("Invalid choice entered\nEnter again!\n")

            # --- Here the user has already been authenticated ---
            # Set online status to active
            online = True

            # Start the GUI
            # GUI Instance
            top = None  
            top = tkinter.Tk()
            top.title(f"CHAT APPLICATION [{clientname}]")

            # Message Box: Transmits messages to the server
            messages_frame = tkinter.Frame(top)
            message_sent = tkinter.StringVar()
            message_sent.set("Type your messages here...")

            # Scrollbar to navigate through past messages
            scrollbar = tkinter.Scrollbar(messages_frame)

            # Following will contain the messages (Window displaying messages)
            msg_list = tkinter.Listbox(messages_frame, height=15, width=50, yscrollcommand=scrollbar.set)
            scrollbar.pack(side=tkinter.RIGHT, fill=tkinter.Y)
            msg_list.pack(side=tkinter.LEFT, fill=tkinter.BOTH)
            msg_list.pack()
            messages_frame.pack()

            entry_field = tkinter.Entry(top, textvariable=message_sent)
            entry_field.bind("<Return>", send_data)
            entry_field.pack()
            send_button = tkinter.Button(top, text="Send", command=send_data)
            send_button.pack()

            top.protocol("WM_DELETE_WINDOW", close_GUI_window)

            # Thread to receive data from the server
            receive_thread = Thread(target=receive_data, daemon=True)
            stop_threads = False

            # Thread to interact with the GUI for each client
            interaction_thread = Thread(target=launch_terminal, args=(top, client_sockfd), daemon=True)
            
            receive_thread.start()
            interaction_thread.start()

            # Start GUI execution
            tkinter.mainloop()

            stop_threads = True
            interaction_thread.join()
            top.after(1, top.destroy)
            print("Successfully logged out!")

        except KeyboardInterrupt:
            print("\nCaught Keyboard interrupt.Exitting")
            if online:
                quit_GUI(client_sockfd, top)
            sys.exit(1)

        except ConnectionRefusedError:
            print(f"The server ({HOST}:{PORT}) is not active\n--------- Exitting client ---------\n")
            if online:
                quit_GUI(client_sockfd, top)
            sys.exit(1)

        except OSError as err:
            if err.errno == 101:
                print("Unreachable Network\n--------- Exitting client ---------\n")
            elif err.errno == 22:
                print(f"Invalid Host Address <{HOST}:{PORT}>\n--------- Exitting client ---------\n")
            sys.exit(1)
