import socket

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('localhost', 12345))  # Use '0.0.0.0' to accept external connections
server_socket.listen(1)
print("Server is listening on port 12345...")

try:
    conn, addr = server_socket.accept()
    print(f"Connected by {addr}")

    while True:
        try:
            data = conn.recv(1024)
            if not data:
                print("Client disconnected.")
                break

            message = data.decode().strip()
            print("Client says:", message)

            if message.lower() == "quit_connection":
                conn.sendall("Connection closed.".encode())
                break
            elif message.lower() == "ping":
                conn.sendall("pong".encode())
            else:
                conn.sendall("say 'ping' or 'quit_connection'".encode())

        except ConnectionResetError:
            print("Client forcibly closed the connection.")
            break

except KeyboardInterrupt:
    print("Server manually stopped.")

finally:
    conn.close()
    server_socket.close()
    print("Server shutdown.")
