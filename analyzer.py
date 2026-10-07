from scapy.all import rdpcap, TCP, IP
import argparse
import json
import os

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
DEFAULT_PCAP_FILE = os.path.join(PROJECT_ROOT, "capture", "tcp_zero_window.pcapng")
DEFAULT_RESULT_FILE = os.path.join(PROJECT_ROOT, "results", "analysis.json")
SERVER_PORT = 5000
MIN_STALL_DURATION_SEC = 0.001
RECOVERY_DEBOUNCE_SEC = 0.050  # 50 ms debounce to confirm window recovery (avoids false splits from transient updates)

parser = argparse.ArgumentParser(description="Analyze a TCP-ZeroGuard packet capture.")
parser.add_argument("--pcap", default=DEFAULT_PCAP_FILE, help="PCAP file to analyze")
parser.add_argument("--output", default=DEFAULT_RESULT_FILE, help="JSON output path")
args = parser.parse_args()
PCAP_FILE = args.pcap
RESULT_FILE = args.output


# ---------------------------------------------------------
# LOAD CAPTURE
# ---------------------------------------------------------

print(f"Analyzer input PCAP : {PCAP_FILE}")
print(f"Analyzer output JSON: {RESULT_FILE}")

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
outstanding_probe_seq = None
outstanding_probe_ack = None
previous_probe_time = None

zero_window_packet_count = 0
probe_count = 0
probe_response_count = 0

stall_episode_count = 0
recovery_count = 0

stall_durations = []

currently_stalled = False

timeline = []
pending_recovery = None


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
            outstanding_probe_seq = seq
            outstanding_probe_ack = ack
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

        # Confirm a recovery only after the positive window remains stable.
        # A zero-window update arriving within the debounce interval belongs
        # to the same stall, not a new episode separated by a packet blip.
        if pending_recovery is not None:
            pending_gap = packet_time - pending_recovery["time"]

            if window == 0 and pending_gap < RECOVERY_DEBOUNCE_SEC:
                pending_recovery = None
            elif pending_gap >= RECOVERY_DEBOUNCE_SEC:
                recovery = pending_recovery
                recovery_count += 1
                zero_window_active = False
                currently_stalled = False
                stall_durations.append(recovery["duration"])

                event = {
                    "packet": recovery["packet"],
                    "event": "WINDOW_REOPENED",
                    "timestamp_sec": recovery["time"],
                    "window": recovery["window"],
                    "seq": recovery["seq"],
                    "ack": recovery["ack"],
                    "payload_length": recovery["payload_length"],
                    "start_timestamp_sec": zero_window_start_time,
                    "recovery_timestamp_sec": recovery["time"],
                    "stall_duration": recovery["duration"]
                }

                if zero_window_start_event is not None:
                    zero_window_start_event["stall_duration"] = recovery["duration"]

                timeline.append(event)
                print(
                    f"[WINDOW REOPENED] Packet {recovery['packet']} | "
                    f"Window={recovery['window']} | "
                    f"Stall={recovery['duration']:.3f} sec"
                )
                zero_window_start_time = None
                zero_window_start_event = None
                pending_recovery = None
            # Short positive updates remain provisional while the current
            # packet still participates in probe and zero-window detection.

        # -------------------------------------------------
        # PROBE RESPONSE
        # -------------------------------------------------

        if (
            zero_window_active
            and waiting_for_probe_response
            and ack_flag
            and payload_length == 0
            and outstanding_probe_seq is not None
            and outstanding_probe_ack is not None
            and seq == outstanding_probe_ack
            and ack in (
                outstanding_probe_seq,
                (outstanding_probe_seq + 1) & 0xFFFFFFFF
            )
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
            outstanding_probe_seq = None
            outstanding_probe_ack = None

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
                outstanding_probe_seq = None
                outstanding_probe_ack = None

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
            and pending_recovery is None
        ):
            if zero_window_start_time is not None:
                duration = (
                    packet_time
                    - zero_window_start_time
                )

                # Loopback captures can contain a transient non-zero window
                # update only microseconds after a zero-window ACK. Do not
                # split one continuous stall into artificial episodes.
                if duration < MIN_STALL_DURATION_SEC:
                    continue

                pending_recovery = {
                    "packet": packet_number,
                    "time": packet_time,
                    "window": window,
                    "seq": seq,
                    "ack": ack,
                    "payload_length": payload_length,
                    "duration": duration
                }

            else:
                recovery_count += 1
                zero_window_active = False
                currently_stalled = False


# ---------------------------------------------------------
# CALCULATE STATISTICS
# ---------------------------------------------------------

# If the capture ends after a positive window with no quick zero-window
# rebound, the observed recovery is confirmed by the end of the capture.
if pending_recovery is not None:
    recovery = pending_recovery
    recovery_count += 1
    zero_window_active = False
    currently_stalled = False
    stall_durations.append(recovery["duration"])
    event = {
        "packet": recovery["packet"],
        "event": "WINDOW_REOPENED",
        "timestamp_sec": recovery["time"],
        "window": recovery["window"],
        "seq": recovery["seq"],
        "ack": recovery["ack"],
        "payload_length": recovery["payload_length"],
        "start_timestamp_sec": zero_window_start_time,
        "recovery_timestamp_sec": recovery["time"],
        "stall_duration": recovery["duration"]
    }
    if zero_window_start_event is not None:
        zero_window_start_event["stall_duration"] = recovery["duration"]
    timeline.append(event)
    print(
        f"[WINDOW REOPENED] Packet {recovery['packet']} | "
        f"Window={recovery['window']} | "
        f"Stall={recovery['duration']:.3f} sec"
    )

timeline.sort(key=lambda event: (event["timestamp_sec"], event["packet"]))

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
# ROOT CAUSE ANALYSIS
# ---------------------------------------------------------

def determine_root_cause(metrics, state):
    """
    Determine the root cause of TCP performance issues based on
    existing zero-window metrics and connection state.
    
    Args:
        metrics: Dict with zero_window_packets, stall_episodes, confirmed_probes,
                 probe_responses, recovery_episodes, total_stall_duration_sec,
                 maximum_stall_duration_sec, average_stall_duration_sec
        state: Dict with stall_detected, recovery_detected, currently_stalled
    
    Returns:
        Dict with status, likely_cause, explanation, impact, recommendation
    """
    zero_window_packets = metrics.get("zero_window_packets", 0)
    stall_episodes = metrics.get("stall_episodes", 0)
    recovery_episodes = metrics.get("recovery_episodes", 0)
    currently_stalled = state.get("currently_stalled", False)
    stall_detected = state.get("stall_detected", False)
    recovery_detected = state.get("recovery_detected", False)

    # No zero-window condition detected
    if zero_window_packets == 0 and not stall_detected:
        return {
            "status": "HEALTHY",
            "likely_cause": "No significant receive-window stall detected",
            "explanation": "The receiver continued advertising available TCP receive-window capacity throughout the capture.",
            "impact": "No significant TCP receive-window impact detected.",
            "recommendation": "No receive-window action required."
        }

    # Currently stalled - receiver is advertising zero window right now
    if currently_stalled:
        return {
            "status": "CURRENTLY STALLED",
            "likely_cause": "Receiver-side processing/read delay",
            "explanation": "The receiver is currently advertising a zero TCP receive window, indicating it cannot accept additional data at this moment. Normal transmission is being restricted by receiver-side flow control.",
            "impact": "TCP transmission is currently stalled by receiver-side flow control. The sender cannot transmit new data until the window reopens.",
            "recommendation": "Check receiver processing speed, application read delays, and receive-buffer availability immediately."
        }

    # Zero-window events occurred but recovery was detected
    if stall_detected and recovery_detected:
        return {
            "status": "RECOVERED",
            "likely_cause": "Receiver-side processing/read delay (now resolved)",
            "explanation": f"The receiver advertised a zero TCP receive window {stall_episodes} time(s), indicating temporary inability to accept data. The receive window later reopened ({recovery_episodes} recovery episode(s) detected) and transmission recovered.",
            "impact": f"TCP transmission was temporarily stalled by receiver-side flow control. Total stall duration: {metrics.get('total_stall_duration_sec', 0):.3f}s. Maximum single stall: {metrics.get('maximum_stall_duration_sec', 0):.3f}s.",
            "recommendation": "Check receiver processing speed, application read delays, and receive-buffer sizing. Consider increasing socket receive buffer (SO_RCVBUF) if stalls are frequent."
        }

    # Zero-window detected but no recovery (edge case)
    if stall_detected and not recovery_detected:
        return {
            "status": "STALL DETECTED (UNRESOLVED)",
            "likely_cause": "Receiver-side processing/read delay",
            "explanation": f"The receiver advertised a zero TCP receive window {stall_episodes} time(s), but no window reopening was detected in the capture. The stall may still be ongoing or the capture ended before recovery.",
            "impact": "TCP transmission was stalled by receiver-side flow control. Recovery status unknown.",
            "recommendation": "Verify if the receiver is still running and able to process data. Check for application hangs or buffer exhaustion."
        }

    # Fallback
    return {
        "status": "UNKNOWN",
        "likely_cause": "Indeterminate",
        "explanation": "Unable to determine root cause from available metrics.",
        "impact": "Unknown.",
        "recommendation": "Review raw packet capture for additional context."
    }


root_cause = determine_root_cause(
    {
        "zero_window_packets": zero_window_packet_count,
        "stall_episodes": stall_episode_count,
        "confirmed_probes": probe_count,
        "probe_responses": probe_response_count,
        "recovery_episodes": recovery_count,
        "total_stall_duration_sec": round(total_stall_duration, 3),
        "maximum_stall_duration_sec": round(maximum_stall_duration, 3),
        "average_stall_duration_sec": round(average_stall_duration, 3)
    },
    {
        "stall_detected": stall_episode_count > 0,
        "recovery_detected": recovery_count > 0,
        "currently_stalled": currently_stalled
    }
)

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

        "currently_stalled": currently_stalled
    },

    "root_cause_analysis": root_cause,

    "timeline": timeline
}


# ---------------------------------------------------------
# SAVE JSON RESULT
# ---------------------------------------------------------

os.makedirs(
    os.path.dirname(RESULT_FILE) or ".",
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
