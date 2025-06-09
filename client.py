# client.py
import socket

# Step 1: Create socket and connect
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('localhost', 12345))

# Step 2: Send a ping
client_socket.sendall("ping".encode())

# Step 3: Receive response
data = client_socket.recv(1024).decode()
print("Server replies:", data)

# Step 4: Close connection
client_socket.close()
