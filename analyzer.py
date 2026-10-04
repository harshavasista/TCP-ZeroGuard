from scapy.all import rdpcap, TCP, IP
import json
import os

PCAP_FILE = "capture/tcp_zero_window.pcapng"
RESULT_FILE = "results/analysis.json"
SERVER_PORT = 5000


# ---------------------------------------------------------
# LOAD CAPTURE
# ---------------------------------------------------------

packets = rdpcap(PCAP_FILE)

print("========== TCP-ZeroGuard ==========")
print()


# ---------------------------------------------------------
# EXTRACT TCP PACKETS
# ---------------------------------------------------------

tcp_packets = []

for packet_number, packet in enumerate(packets, start=1):

    if TCP not in packet or IP not in packet:
        continue

    tcp = packet[TCP]

    tcp_packets.append({
        "packet_number": packet_number,
        "time": float(packet.time),
        "src": (packet[IP].src, tcp.sport),
        "dst": (packet[IP].dst, tcp.dport),
        "seq": tcp.seq,
        "ack": tcp.ack,
        "window": tcp.window,
        "payload_length": len(bytes(tcp.payload)),
        "flags": int(tcp.flags)
    })


# Process by capture timestamp, using packet number to preserve capture order
# when timestamps have the same resolution.
tcp_packets.sort(
    key=lambda info: (
        info["time"],
        info["packet_number"]
    )
)


print(f"Total packets captured : {len(packets)}")
print(f"TCP packets detected   : {len(tcp_packets)}")
print()

if not tcp_packets:
    print("No TCP packets found.")
    raise SystemExit


# ---------------------------------------------------------
# IDENTIFY SENDER AND RECEIVER
# ---------------------------------------------------------

sender_endpoint = None
receiver_endpoint = None

for info in tcp_packets:

    if info["dst"][1] == SERVER_PORT:
        sender_endpoint = info["src"]
        receiver_endpoint = info["dst"]
        break

    if info["src"][1] == SERVER_PORT:
        receiver_endpoint = info["src"]
        sender_endpoint = info["dst"]
        break


if sender_endpoint is None or receiver_endpoint is None:

    print("Could not identify sender and receiver.")
    raise SystemExit


print("========== TCP CONNECTION ==========")

print(
    f"Sender   : "
    f"{sender_endpoint[0]}:{sender_endpoint[1]}"
)

print(
    f"Receiver : "
    f"{receiver_endpoint[0]}:{receiver_endpoint[1]}"
)

print()


# ---------------------------------------------------------
# STATE VARIABLES
# ---------------------------------------------------------

zero_window_active = False
zero_window_start_time = None
zero_window_start_event = None
last_zero_window_ack = None
waiting_for_probe_response = False
outstanding_probe_time = None
previous_probe_time = None

zero_window_packet_count = 0
probe_count = 0
probe_response_count = 0

stall_episode_count = 0
recovery_count = 0

stall_durations = []

currently_stalled = False
latest_receiver_window = None
latest_receiver_window_time = None
latest_receiver_window_packet = None

timeline = []


# ---------------------------------------------------------
# PROCESS TCP PACKETS
# ---------------------------------------------------------

for info in tcp_packets:

    packet_number = info["packet_number"]
    packet_time = info["time"]

    src = info["src"]
    dst = info["dst"]

    seq = info["seq"]
    ack = info["ack"]

    window = info["window"]
    payload_length = info["payload_length"]

    flags = info["flags"]

    ack_flag = bool(flags & 0x10)


    # -----------------------------------------------------
    # DETERMINE DIRECTION
    # -----------------------------------------------------

    if src == sender_endpoint and dst == receiver_endpoint:

        direction = "SENDER -> RECEIVER"

    elif src == receiver_endpoint and dst == sender_endpoint:

        direction = "RECEIVER -> SENDER"

    else:

        continue


    # =====================================================
    # SENDER -> RECEIVER
    # =====================================================

    if direction == "SENDER -> RECEIVER":

        if (
            zero_window_active
            and payload_length == 1
            and last_zero_window_ack is not None
            and seq == last_zero_window_ack
        ):

            probe_count += 1

            waiting_for_probe_response = True
            probe_interval_start = (
                previous_probe_time
                if previous_probe_time is not None
                else zero_window_start_time
            )

            event = {
                "packet": packet_number,
                "event": "ZERO_WINDOW_PROBE",
                "timestamp_sec": packet_time,
                "seq": seq,
                "ack": ack,
                "window": window,
                "payload_length": payload_length,
                "probe_interval_sec": (
                    packet_time - probe_interval_start
                    if probe_interval_start is not None
                    else None
                )
            }

            timeline.append(event)
            outstanding_probe_time = packet_time
            previous_probe_time = packet_time

            print(
                f"[ZERO WINDOW PROBE] "
                f"Packet {packet_number} | "
                f"Seq={seq} | "
                f"Payload=1 byte"
            )


    # =====================================================
    # RECEIVER -> SENDER
    # =====================================================

    elif direction == "RECEIVER -> SENDER":

        # The TCP window field is an advertised receive window on ACK-bearing
        # receiver-to-sender segments. Ignore other segment types as current
        # state evidence while keeping them in the existing event analysis.
        if ack_flag:
            latest_receiver_window = window
            latest_receiver_window_time = packet_time
            latest_receiver_window_packet = packet_number

        # -------------------------------------------------
        # PROBE RESPONSE
        # -------------------------------------------------

        if (
            zero_window_active
            and waiting_for_probe_response
            and ack_flag
            and payload_length == 0
        ):

            probe_response_count += 1

            waiting_for_probe_response = False

            event = {
                "packet": packet_number,
                "event": "PROBE_RESPONSE",
                "timestamp_sec": packet_time,
                "probe_timestamp_sec": outstanding_probe_time,
                "seq": seq,
                "ack": ack,
                "window": window,
                "payload_length": payload_length,
                "probe_response_latency_sec": (
                    packet_time - outstanding_probe_time
                    if outstanding_probe_time is not None
                    else None
                )
            }

            timeline.append(event)
            outstanding_probe_time = None

            print(
                f"[PROBE RESPONSE] "
                f"Packet {packet_number} | "
                f"ACK={ack} | "
                f"Window={window}"
            )


        # -------------------------------------------------
        # ZERO WINDOW
        # -------------------------------------------------

        if window == 0:

            zero_window_packet_count += 1

            last_zero_window_ack = ack

            if not zero_window_active:

                zero_window_active = True
                currently_stalled = True

                zero_window_start_time = packet_time
                previous_probe_time = None
                outstanding_probe_time = None

                stall_episode_count += 1

                event = {
                    "packet": packet_number,
                    "event": "ZERO_WINDOW_START",
                    "timestamp_sec": packet_time,
                    "window": window,
                    "seq": seq,
                    "ack": ack,
                    "payload_length": payload_length,
                    "start_timestamp_sec": packet_time
                }

                timeline.append(event)
                zero_window_start_event = event

                print(
                    f"[ZERO WINDOW START] "
                    f"Packet {packet_number} | "
                    f"Window={window} | "
                    f"ACK={ack}"
                )

            else:

                print(
                    f"[ZERO WINDOW] "
                    f"Packet {packet_number} | "
                    f"Window={window} | "
                    f"ACK={ack}"
                )


        # -------------------------------------------------
        # WINDOW REOPENED
        # -------------------------------------------------

        elif (
            zero_window_active
            and window > 0
        ):

            recovery_count += 1

            zero_window_active = False
            currently_stalled = False

            if zero_window_start_time is not None:

                duration = (
                    packet_time
                    - zero_window_start_time
                )

                stall_durations.append(duration)

                event = {
                    "packet": packet_number,
                    "event": "WINDOW_REOPENED",
                    "timestamp_sec": packet_time,
                    "window": window,
                    "seq": seq,
                    "ack": ack,
                    "payload_length": payload_length,
                    "start_timestamp_sec": zero_window_start_time,
                    "recovery_timestamp_sec": packet_time,
                    "stall_duration": duration
                }

                if zero_window_start_event is not None:
                    zero_window_start_event["stall_duration"] = duration

                timeline.append(event)

                print(
                    f"[WINDOW REOPENED] "
                    f"Packet {packet_number} | "
                    f"Window={window} | "
                    f"Stall={duration:.3f} sec"
                )

                zero_window_start_time = None
                zero_window_start_event = None


# ---------------------------------------------------------
# CALCULATE STATISTICS
# ---------------------------------------------------------

if stall_durations:

    total_stall_duration = sum(stall_durations)

    maximum_stall_duration = max(stall_durations)

    average_stall_duration = (
        total_stall_duration
        / len(stall_durations)
    )

else:

    total_stall_duration = 0.0
    maximum_stall_duration = 0.0
    average_stall_duration = 0.0


# ---------------------------------------------------------
# BUILD RESULT
# ---------------------------------------------------------

analysis_result = {

    "project": "TCP-ZeroGuard",

    "connection": {
        "sender": {
            "ip": sender_endpoint[0],
            "port": sender_endpoint[1]
        },

        "receiver": {
            "ip": receiver_endpoint[0],
            "port": receiver_endpoint[1]
        }
    },

    "capture": {
        "total_packets": len(packets),
        "tcp_packets": len(tcp_packets)
    },

    "events": {
        "zero_window_packets": zero_window_packet_count,
        "stall_episodes": stall_episode_count,
        "confirmed_probes": probe_count,
        "probe_responses": probe_response_count,
        "recovery_episodes": recovery_count
    },

    "metrics": {
        "total_stall_duration_sec": round(
            total_stall_duration,
            3
        ),

        "maximum_stall_duration_sec": round(
            maximum_stall_duration,
            3
        ),

        "average_stall_duration_sec": round(
            average_stall_duration,
            3
        )
    },

    "state": {
        "stall_detected": (
            stall_episode_count > 0
        ),

        "recovery_detected": (
            recovery_count > 0
        ),

        "currently_stalled": currently_stalled,
        "latest_receive_window": latest_receiver_window,
        "latest_receive_window_timestamp_sec": latest_receiver_window_time,
        "latest_receive_window_packet": latest_receiver_window_packet
    },

    "timeline": timeline
}


# ---------------------------------------------------------
# SAVE JSON RESULT
# ---------------------------------------------------------

os.makedirs(
    os.path.dirname(RESULT_FILE),
    exist_ok=True
)

with open(
    RESULT_FILE,
    "w",
    encoding="utf-8"
) as file:

    json.dump(
        analysis_result,
        file,
        indent=4
    )


# ---------------------------------------------------------
# DISPLAY FINAL SUMMARY
# ---------------------------------------------------------

print()
print("========== ANALYSIS SUMMARY ==========")

print(
    f"Zero Window packets    : "
    f"{zero_window_packet_count}"
)

print(
    f"Stall episodes         : "
    f"{stall_episode_count}"
)

print(
    f"Confirmed probes       : "
    f"{probe_count}"
)

print(
    f"Probe responses        : "
    f"{probe_response_count}"
)

print(
    f"Recovery episodes      : "
    f"{recovery_count}"
)

print(
    f"Stall detected         : "
    f"{'YES' if stall_episode_count > 0 else 'NO'}"
)

print(
    f"Currently stalled      : "
    f"{'YES' if currently_stalled else 'NO'}"
)

print(
    f"Recovery detected      : "
    f"{'YES' if recovery_count > 0 else 'NO'}"
)

print(
    f"Total stall duration   : "
    f"{total_stall_duration:.3f} sec"
)

print(
    f"Maximum stall duration : "
    f"{maximum_stall_duration:.3f} sec"
)

print(
    f"Average stall duration : "
    f"{average_stall_duration:.3f} sec"
)

print()
print(
    f"Analysis saved to: {RESULT_FILE}"
)

print()
print("=====================================")
