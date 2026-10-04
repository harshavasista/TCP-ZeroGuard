from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pathlib import Path
import json
import subprocess
import sys
import os
import re
import time


# ============================================================
# TCP-ZeroGuard FastAPI Backend
# ============================================================

app = FastAPI(
    title="TCP-ZeroGuard API",
    description="Automatic TCP receive-window stall capture and analysis",
    version="1.0.0"
)


# ============================================================
# CORS
# ============================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:5500",
        "http://localhost:5500",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# PROJECT PATHS
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

ANALYZER_FILE = PROJECT_ROOT / "analyzer.py"
SENDER_FILE = PROJECT_ROOT / "sender.py"
RECEIVER_FILE = PROJECT_ROOT / "receiver.py"

CAPTURE_DIR = PROJECT_ROOT / "capture"
RESULTS_DIR = PROJECT_ROOT / "results"

PCAP_FILE = CAPTURE_DIR / "tcp_zero_window.pcapng"
ANALYSIS_FILE = RESULTS_DIR / "analysis.json"

DUMPCAP_PATH = Path(
    r"C:\Program Files\Wireshark\dumpcap.exe"
)

CAPTURE_FILTER = "tcp port 5000"


# ============================================================
# DIRECTORY SETUP
# ============================================================

CAPTURE_DIR.mkdir(parents=True, exist_ok=True)
RESULTS_DIR.mkdir(parents=True, exist_ok=True)


# ============================================================
# FIND DUMPCAP
# ============================================================

def find_dumpcap():
    """
    Find dumpcap.exe automatically.

    First checks the known Wireshark installation path.
    Then checks PATH as a fallback.
    """

    possible_paths = [
        Path(r"C:\Program Files\Wireshark\dumpcap.exe"),
        Path(r"C:\Program Files (x86)\Wireshark\dumpcap.exe"),
    ]

    for path in possible_paths:
        if path.exists():
            return path

    try:
        result = subprocess.run(
            ["where", "dumpcap"],
            capture_output=True,
            text=True,
            timeout=10
        )

        if result.returncode == 0:
            first_line = result.stdout.strip().splitlines()

            if first_line:
                path = Path(first_line[0].strip())

                if path.exists():
                    return path

    except Exception:
        pass

    return None


# ============================================================
# FIND Npcap LOOPBACK INTERFACE
# ============================================================

def find_loopback_interface(dumpcap_path):
    """
    Uses dumpcap -D to find the Npcap loopback interface.

    The interface used previously in Wireshark is normally named:

        Adapter for loopback traffic capture
    """

    try:
        result = subprocess.run(
            [
                str(dumpcap_path),
                "-D"
            ],
            capture_output=True,
            text=True,
            timeout=15
        )

    except Exception as error:
        raise RuntimeError(
            f"Unable to list capture interfaces: {error}"
        )

    if result.returncode != 0:
        raise RuntimeError(
            "dumpcap could not list network interfaces.\n"
            f"Error: {result.stderr}"
        )

    output = result.stdout

    print("\n========== DUMPCAP INTERFACES ==========")
    print(output)
    print("========================================\n")

    for line in output.splitlines():

        if "loopback" not in line.lower():
            continue

        match = re.match(
            r"^\s*(\d+)\.\s+(\S+)\s+\((.*?)\)\s*$",
            line
        )

        if match:
            interface_number = match.group(1)
            interface_name = match.group(2)
            description = match.group(3)

            print(
                "Loopback interface detected:"
            )
            print(
                f"Number      : {interface_number}"
            )
            print(
                f"Interface   : {interface_name}"
            )
            print(
                f"Description : {description}"
            )

            return interface_number

    raise RuntimeError(
        "Npcap loopback interface was not found.\n\n"
        "Open Wireshark and verify that "
        "'Adapter for loopback traffic capture' "
        "is available."
    )


# ============================================================
# READ ANALYSIS JSON
# ============================================================

def read_analysis():

    if not ANALYSIS_FILE.exists():
        raise HTTPException(
            status_code=404,
            detail=(
                "analysis.json not found. "
                "Run an analysis first."
            )
        )

    try:

        with open(
            ANALYSIS_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            return json.load(file)

    except json.JSONDecodeError:

        raise HTTPException(
            status_code=500,
            detail="analysis.json contains invalid JSON."
        )

    except Exception as error:

        raise HTTPException(
            status_code=500,
            detail=(
                f"Unable to read analysis.json: "
                f"{error}"
            )
        )


# ============================================================
# ROOT
# ============================================================

@app.get("/")
def root():

    return {
        "project": "TCP-ZeroGuard",
        "status": "API running",
        "automatic_capture": True
    }


# ============================================================
# GET CURRENT ANALYSIS
# ============================================================

@app.get("/api/analysis")
def get_analysis():

    return read_analysis()


# ============================================================
# AUTOMATIC CAPTURE + TEST + ANALYSIS
# ============================================================

@app.post("/api/start-capture")
def start_capture():

    dumpcap_path = find_dumpcap()

    if dumpcap_path is None:

        raise HTTPException(
            status_code=500,
            detail=(
                "dumpcap.exe was not found.\n"
                "Expected location:\n"
                "C:\\Program Files\\Wireshark\\dumpcap.exe"
            )
        )

    if not ANALYZER_FILE.exists():

        raise HTTPException(
            status_code=404,
            detail="analyzer.py not found."
        )

    if not SENDER_FILE.exists():

        raise HTTPException(
            status_code=404,
            detail="sender.py not found."
        )

    if not RECEIVER_FILE.exists():

        raise HTTPException(
            status_code=404,
            detail="receiver.py not found."
        )

    try:

        # ----------------------------------------------------
        # Find loopback interface
        # ----------------------------------------------------

        interface = find_loopback_interface(
            dumpcap_path
        )

        # ----------------------------------------------------
        # Remove previous capture
        # ----------------------------------------------------

        if PCAP_FILE.exists():

            try:
                PCAP_FILE.unlink()

            except PermissionError:

                raise HTTPException(
                    status_code=500,
                    detail=(
                        "Previous PCAP file is currently "
                        "being used by another program. "
                        "Close Wireshark and try again."
                    )
                )

        # ----------------------------------------------------
        # START DUMPCAP
        # ----------------------------------------------------

        print()
        print("========================================")
        print("       TCP-ZeroGuard AUTOMATIC TEST")
        print("========================================")
        print()

        print("Dumpcap:")
        print(dumpcap_path)

        print()
        print("Capture interface:")
        print(interface)

        print()
        print("Capture filter:")
        print(CAPTURE_FILTER)

        print()
        print("Output:")
        print(PCAP_FILE)

        print()
        print("Starting packet capture...")

        capture_process = subprocess.Popen(
            [
                str(dumpcap_path),

                "-i",
                str(interface),

                "-f",
                CAPTURE_FILTER,

                "-w",
                str(PCAP_FILE),

                "-q"
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True
        )

        # Give Dumpcap time to initialize.
        time.sleep(2)

        if capture_process.poll() is not None:

            stderr = ""

            if capture_process.stderr:

                stderr = capture_process.stderr.read()

            raise RuntimeError(
                "Dumpcap stopped unexpectedly.\n"
                f"{stderr}"
            )

        print("Packet capture started.")

        # ----------------------------------------------------
        # START RECEIVER
        # ----------------------------------------------------

        print()
        print("Starting receiver...")

        receiver_log = RESULTS_DIR / "receiver_last_run.log"

        receiver_output = open(
            receiver_log,
            "w",
            encoding="utf-8"
        )

        receiver_process = subprocess.Popen(
            [
                sys.executable,
                str(RECEIVER_FILE)
            ],
            cwd=str(PROJECT_ROOT),
            stdout=receiver_output,
            stderr=subprocess.STDOUT,
            text=True
        )

        # Give receiver time to bind port 5000.
        time.sleep(2)

        if receiver_process.poll() is not None:

            receiver_output.close()

            raise RuntimeError(
                "Receiver stopped before the sender started."
            )

        print("Receiver started.")

        # ----------------------------------------------------
        # START SENDER
        # ----------------------------------------------------

        print()
        print("Starting sender...")

        sender_log = RESULTS_DIR / "sender_last_run.log"

        sender_output = open(
            sender_log,
            "w",
            encoding="utf-8"
        )

        sender_process = subprocess.Popen(
            [
                sys.executable,
                str(SENDER_FILE)
            ],
            cwd=str(PROJECT_ROOT),
            stdout=sender_output,
            stderr=subprocess.STDOUT,
            text=True
        )

        print("Sender started.")

        # ----------------------------------------------------
        # WAIT FOR TEST
        # ----------------------------------------------------

        print()
        print("TCP test is running...")
        print(
            "Waiting for sender/receiver "
            "to complete..."
        )

        test_timeout = 60

        test_start = time.time()

        while True:

            sender_finished = (
                sender_process.poll() is not None
            )

            receiver_finished = (
                receiver_process.poll() is not None
            )

            if sender_finished and receiver_finished:
                break

            if time.time() - test_start > test_timeout:

                print(
                    "Test timeout reached."
                )

                break

            time.sleep(0.5)

        # ----------------------------------------------------
        # CLEAN UP TEST PROCESSES
        # ----------------------------------------------------

        if sender_process.poll() is None:

            sender_process.terminate()

            try:

                sender_process.wait(
                    timeout=5
                )

            except subprocess.TimeoutExpired:

                sender_process.kill()

        if receiver_process.poll() is None:

            receiver_process.terminate()

            try:

                receiver_process.wait(
                    timeout=5
                )

            except subprocess.TimeoutExpired:

                receiver_process.kill()

        sender_output.close()
        receiver_output.close()

        print()
        print("Sender/receiver test finished.")

        # ----------------------------------------------------
        # STOP DUMPCAP
        # ----------------------------------------------------

        print()
        print("Stopping packet capture...")

        if capture_process.poll() is None:

            capture_process.terminate()

            try:

                capture_process.wait(
                    timeout=10
                )

            except subprocess.TimeoutExpired:

                capture_process.kill()

                capture_process.wait()

        print("Packet capture stopped.")

        # ----------------------------------------------------
        # VERIFY PCAP
        # ----------------------------------------------------

        if not PCAP_FILE.exists():

            raise RuntimeError(
                "Capture finished but the PCAP file "
                "was not created."
            )

        pcap_size = PCAP_FILE.stat().st_size

        print()
        print(
            f"PCAP created successfully: "
            f"{pcap_size} bytes"
        )

        # ----------------------------------------------------
        # RUN ANALYZER
        # ----------------------------------------------------

        print()
        print("Running TCP-ZeroGuard analyzer...")

        analyzer_result = subprocess.run(
            [
                sys.executable,
                str(ANALYZER_FILE)
            ],
            cwd=str(PROJECT_ROOT),
            capture_output=True,
            text=True,
            timeout=120
        )

        if analyzer_result.returncode != 0:

            raise RuntimeError(
                "Analyzer failed.\n\n"
                f"STDOUT:\n"
                f"{analyzer_result.stdout}\n\n"
                f"STDERR:\n"
                f"{analyzer_result.stderr}"
            )

        # ----------------------------------------------------
        # VERIFY ANALYSIS
        # ----------------------------------------------------

        if not ANALYSIS_FILE.exists():

            raise RuntimeError(
                "Analyzer completed but "
                "analysis.json was not generated."
            )

        analysis = read_analysis()

        # ----------------------------------------------------
        # FINAL RESULT
        # ----------------------------------------------------

        print()
        print("========================================")
        print("       TCP-ZeroGuard TEST COMPLETE")
        print("========================================")
        print()

        print(
            f"PCAP packets : "
            f"{analysis.get('capture', {}).get('total_packets', 0)}"
        )

        print(
            f"Zero windows : "
            f"{analysis.get('events', {}).get('zero_window_packets', 0)}"
        )

        print(
            f"Stall episodes : "
            f"{analysis.get('events', {}).get('stall_episodes', 0)}"
        )

        print(
            f"Probes : "
            f"{analysis.get('events', {}).get('confirmed_probes', 0)}"
        )

        print(
            f"Recoveries : "
            f"{analysis.get('events', {}).get('recovery_episodes', 0)}"
        )

        print()

        return {
            "status": "Automatic capture and analysis completed",
            "capture": {
                "interface": interface,
                "filter": CAPTURE_FILTER,
                "pcap_file": str(PCAP_FILE),
                "pcap_size_bytes": pcap_size
            },
            "analysis": analysis,
            "analyzer_output": analyzer_result.stdout
        }

    except HTTPException:

        raise

    except Exception as error:

        # ----------------------------------------------------
        # CLEANUP IF SOMETHING GOES WRONG
        # ----------------------------------------------------

        try:

            if "sender_process" in locals():

                if sender_process.poll() is None:
                    sender_process.terminate()

        except Exception:
            pass

        try:

            if "receiver_process" in locals():

                if receiver_process.poll() is None:
                    receiver_process.terminate()

        except Exception:
            pass

        try:

            if "capture_process" in locals():

                if capture_process.poll() is None:

                    capture_process.terminate()

                    try:
                        capture_process.wait(
                            timeout=5
                        )

                    except subprocess.TimeoutExpired:
                        capture_process.kill()

        except Exception:
            pass

        raise HTTPException(
            status_code=500,
            detail=(
                "Automatic capture failed:\n"
                f"{error}"
            )
        )


# ============================================================
# MANUAL ANALYZER ENDPOINT
# ============================================================

@app.post("/api/analyze")
def analyze_pcap():

    if not ANALYZER_FILE.exists():

        raise HTTPException(
            status_code=404,
            detail="analyzer.py not found."
        )

    if not PCAP_FILE.exists():

        raise HTTPException(
            status_code=404,
            detail=(
                "PCAP file not found: "
                "capture/tcp_zero_window.pcapng"
            )
        )

    try:

        result = subprocess.run(
            [
                sys.executable,
                str(ANALYZER_FILE)
            ],
            cwd=str(PROJECT_ROOT),
            capture_output=True,
            text=True,
            timeout=120
        )

        if result.returncode != 0:

            raise HTTPException(
                status_code=500,
                detail={
                    "message": "Analyzer failed.",
                    "stdout": result.stdout,
                    "stderr": result.stderr
                }
            )

        analysis = read_analysis()

        return {
            "status": "Analysis completed",
            "analyzer_output": result.stdout,
            "analysis": analysis
        }

    except HTTPException:

        raise

    except subprocess.TimeoutExpired:

        raise HTTPException(
            status_code=500,
            detail=(
                "Analyzer timed out after "
                "120 seconds."
            )
        )

    except Exception as error:

        raise HTTPException(
            status_code=500,
            detail=(
                f"Unable to run analyzer: "
                f"{error}"
            )
        )