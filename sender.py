import socket
import time
import os
import random

HOST = "127.0.0.1"
PORT = 5000

# ---------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------

TEST_DURATION = 35       # seconds
MIN_CHUNK_SIZE = 2048    # minimum bytes per send
MAX_CHUNK_SIZE = 8192    # maximum bytes per send

# ---------------------------------------------------------
# CREATE TCP SOCKET
# ---------------------------------------------------------

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

client.settimeout(2)

print("Connecting to receiver...")

client.connect((HOST, PORT))

print("Connected to receiver.")
print()

# ---------------------------------------------------------
# SEND DATA
# ---------------------------------------------------------

total_sent = 0
start_time = time.time()

send_blocked_count = 0

print("Starting TCP transmission...")
print("Generating different data for every transmission...")
print()

try:

    while time.time() - start_time < TEST_DURATION:

        # -------------------------------------------------
        # GENERATE DIFFERENT DATA FOR EVERY SEND
        # -------------------------------------------------

        current_chunk_size = random.randint(
            MIN_CHUNK_SIZE,
            MAX_CHUNK_SIZE
        )

        # Generate random binary data
        data = os.urandom(current_chunk_size)

        # -------------------------------------------------
        # SEND DATA
        # -------------------------------------------------

        send_start = time.time()

        try:

            sent = client.send(data)

            elapsed = time.time() - send_start

            total_sent += sent

            print(
                f"Sent: {total_sent / 1024:.1f} KB | "
                f"Chunk: {current_chunk_size} bytes | "
                f"Send time: {elapsed:.3f} sec"
            )

        except socket.timeout:

            send_blocked_count += 1

            print(
                ">>> SEND BLOCKED: "
                "TCP flow control may be active"
            )

            continue

        except (
            ConnectionResetError,
            BrokenPipeError,
            ConnectionAbortedError
        ):

            print()
            print("Receiver closed the connection.")
            break

        # Small delay to make TCP behavior easier to observe
        time.sleep(0.01)

# ---------------------------------------------------------
# FINISH
# ---------------------------------------------------------

finally:

    print()
    print("========== SENDER SUMMARY ==========")

    duration = time.time() - start_time

    print(
        f"Total data sent : "
        f"{total_sent / 1024:.1f} KB"
    )

    print(
        f"Test duration   : "
        f"{duration:.2f} sec"
    )

    print(
        f"Send blocks     : "
        f"{send_blocked_count}"
    )

    print(
        "===================================="
    )

    client.close()