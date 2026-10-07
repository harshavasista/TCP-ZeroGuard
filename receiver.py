import socket
import time
import argparse
import os

parser = argparse.ArgumentParser(description="TCP-ZeroGuard receiver test")
parser.add_argument("--pause-seconds", type=float, nargs="+", default=[10.0, 10.0])
args = parser.parse_args()

STALL_CYCLES = len(args.pause_seconds)
RECOVERY_READ_SECONDS = 2.0

HOST = "127.0.0.1"
PORT = 5000

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Deliberately use a small receive buffer
server.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)

server.bind((HOST, PORT))
server.listen(1)

print(f"Receiver PID: {os.getpid()}")
print(f"Pause schedule: {list(args.pause_seconds)}")
print(f"Stall cycles: {STALL_CYCLES}")
print(f"Recovery read seconds: {RECOVERY_READ_SECONDS}")

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
# PHASE 2: REPEAT A REAL STOP/RESUME CYCLE
# =========================================================

connection_open = True

for cycle in range(1, STALL_CYCLES + 1):
    print()
    print(f"*** STALL CYCLE {cycle}/{STALL_CYCLES}: STOPPING APPLICATION READS ***")
    pause_seconds = args.pause_seconds[cycle - 1]
    print(f"Receiver will stop reading for {pause_seconds:g} seconds.")
    print("The TCP receive buffer should fill.")
    print()

    time.sleep(pause_seconds)

    if cycle == STALL_CYCLES:
        break

    print(f"*** STALL CYCLE {cycle}: RESUMING READS ***")
    recovery_deadline = time.monotonic() + RECOVERY_READ_SECONDS

    while time.monotonic() < recovery_deadline:
        try:
            data = conn.recv(4096)
            if not data:
                connection_open = False
                break
        except ConnectionResetError:
            connection_open = False
            break

    if not connection_open:
        break


# =========================================================
# FINAL DRAIN / RECOVERY
# =========================================================

print()
print("*** RESUMING APPLICATION READS UNTIL SENDER CLOSES ***")
print()

while connection_open:

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
