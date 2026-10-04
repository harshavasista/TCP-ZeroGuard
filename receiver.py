import socket
import time

HOST = "127.0.0.1"
PORT = 5000

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Deliberately use a small receive buffer
server.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)

server.bind((HOST, PORT))
server.listen(1)

print("Waiting for sender...")

conn, addr = server.accept()

print("Connected:", addr)

# =========================================================
# PHASE 1: NORMAL READING
# =========================================================

print()
print("PHASE 1: Receiver is reading normally for 5 seconds...")

start_time = time.time()

while time.time() - start_time < 5:

    try:
        data = conn.recv(4096)

        if not data:
            print("Sender closed the connection.")
            break

    except ConnectionResetError:
        print("Connection reset by sender.")
        conn.close()
        server.close()
        raise SystemExit


# =========================================================
# PHASE 2: STOP READING
# =========================================================

print()
print("*** PHASE 2: STOPPING APPLICATION READS ***")
print("Receiver will stop reading for 10 seconds.")
print("The TCP receive buffer should fill.")
print()

time.sleep(10)


# =========================================================
# PHASE 3: RESUME READING
# =========================================================

print()
print("*** PHASE 3: RESUMING APPLICATION READS ***")
print("Receiver is reading again.")
print()

start_time = time.time()

while time.time() - start_time < 15:

    try:
        data = conn.recv(4096)

        if not data:
            print("Sender closed the connection.")
            break

        print(
            f"Receiver consumed {len(data)} bytes"
        )

    except ConnectionResetError:
        print("Connection reset by sender.")
        break


# =========================================================
# CLEANUP
# =========================================================

print()
print("Receiver finished.")

conn.close()
server.close()