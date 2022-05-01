# Multithreaded-Chat-App

### Project Members
- **Guruvansh Singh Bhatia**
- **Gaurav Madkaikar**

## File Structure
```bash
├── client.py
├── server.py
├── database/
│   ├── userbase.json
|   ├── backup/
│   │   ├── chat_backup.txt
├── Project_Design.pdf
├── README.md
├── LICENSE
```

## Steps to run the code
Run both the server and the client concurrently. Ensure that the server is running before the client starts since it is a TCP connection.
```bash
    python client.py
```
If server and client are running on the same machine, use hostname as localhost(i.e, 127.0.0.1) 
```bash
    python server.py <hostname> <port>
```
Credentials for the guest user (ALready registered in the user database)
```bash
    Username: guest
    Password: guest123
```

#### Project_Design.pdf contains a brief description of all defined functions including the operational flow of code.
