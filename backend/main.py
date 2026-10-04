import socket
import time
import argparse
import json
import subprocess
import sys
import os
import re
import threading
import uuid
import random
from pathlib import Path
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

try:
    import msvcrt
except ImportError:
    msvcrt = None
    import fcntl


# ============================================================
# TCP-ZeroGuard FastAPI Backend
# ============================================================


app = FastAPI(
    title="TCP-ZeroGuard API",
    description="Automatic TCP receive-window stall capture and analysis",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://tcp-zeroguard-1.onrender.com",
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
RUN_STATE_FILE = RESULTS_DIR / "latest_run.json"
SCENARIO_STATE_FILE = RESULTS_DIR / "scenario_state.json"
RUN_LOCK_FILE = RESULTS_DIR / ".capture.lock"
CURRENT_PCAP_FILE = None
CURRENT_ANALYSIS_FILE = None
RUN_LOCK = threading.Lock()

DUMPCAP_PATH = Path(
    r"C:\Program Files\Wireshark\dumpcap.exe"
)

CAPTURE_FILTER = "tcp port 5000"
DEFAULT_PAUSE_SCHEDULES = (
    (3.0, 5.0),
    (5.0, 8.0, 3.0),
    (4.0, 7.0)
)


# ============================================================
# DIRECTORY SETUP
# ============================================================

CAPTURE_DIR.mkdir(parents=True, exist_ok=True)
RESULTS_DIR.mkdir(parents=True, exist_ok=True)


def acquire_run_lock():
    if not RUN_LOCK.acquire(blocking=False):
        return None

    lock_file = None
    try:
        lock_file = open(RUN_LOCK_FILE, "a+b")
        if lock_file.seek(0, os.SEEK_END) == 0:
            lock_file.write(b"\0")
            lock_file.flush()
        lock_file.seek(0)

        if msvcrt is not None:
            msvcrt.locking(lock_file.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        if lock_file is not None:
            lock_file.close()
        RUN_LOCK.release()
        return None

    return lock_file


def release_run_lock(lock_file):
    try:
        if msvcrt is not None:
            lock_file.seek(0)
            msvcrt.locking(lock_file.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
    finally:
        lock_file.close()
        RUN_LOCK.release()


def save_run_state(status, run_id=None, pcap_file=None, analysis_file=None):
    state = {"status": status, "run_id": run_id}
    if pcap_file is not None:
        state["pcap_file"] = str(pcap_file)
    if analysis_file is not None:
        state["analysis_file"] = str(analysis_file)

    temporary_file = RUN_STATE_FILE.with_suffix(".tmp")
    try:
        with open(temporary_file, "w", encoding="utf-8") as file:
            json.dump(state, file)
        os.replace(temporary_file, RUN_STATE_FILE)
    except OSError as error:
        print(f"Unable to save latest-run state: {error}")


def next_pause_schedule():
    try:
        with open(SCENARIO_STATE_FILE, "r", encoding="utf-8") as file:
            next_index = int(json.load(file).get("next_index", 0))
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        next_index = 0

    scenario_index = next_index % len(DEFAULT_PAUSE_SCHEDULES)
    schedule = DEFAULT_PAUSE_SCHEDULES[scenario_index]
    temporary_file = SCENARIO_STATE_FILE.with_suffix(".tmp")
    try:
        with open(temporary_file, "w", encoding="utf-8") as file:
            json.dump({"next_index": next_index + 1}, file)
        os.replace(temporary_file, SCENARIO_STATE_FILE)
    except OSError as error:
        print(f"Unable to save next test scenario: {error}")

    return schedule, scenario_index


def load_latest_run_state():
    global CURRENT_PCAP_FILE, CURRENT_ANALYSIS_FILE

    CURRENT_PCAP_FILE = None
    CURRENT_ANALYSIS_FILE = None

    if RUN_STATE_FILE.exists():
        try:
            with open(RUN_STATE_FILE, "r", encoding="utf-8") as file:
                state = json.load(file)
            if state.get("status") != "completed":
                return

            pcap_file = Path(state.get("pcap_file", ""))
            analysis_file = Path(state.get("analysis_file", ""))
            if pcap_file.is_file() and pcap_file.stat().st_size > 24 and analysis_file.is_file():
                CURRENT_PCAP_FILE = pcap_file
                CURRENT_ANALYSIS_FILE = analysis_file
            return
        except (OSError, ValueError, TypeError):
            return

    else:
        completed_runs = []
        for analysis_file in RESULTS_DIR.glob("analysis_*.json"):
            run_id = analysis_file.stem[len("analysis_"):]
            pcap_file = CAPTURE_DIR / f"tcp_zero_window_{run_id}.pcapng"
            if pcap_file.is_file() and pcap_file.stat().st_size > 24:
                completed_runs.append((analysis_file.stat().st_mtime, pcap_file, analysis_file))

        if completed_runs:
            _, CURRENT_PCAP_FILE, CURRENT_ANALYSIS_FILE = max(completed_runs, key=lambda run: run[0])
            return

    # Backward compatibility for an existing project capture made before
    # per-run files were introduced.
    if PCAP_FILE.is_file() and PCAP_FILE.stat().st_size > 24 and ANALYSIS_FILE.is_file():
        CURRENT_PCAP_FILE = PCAP_FILE
        CURRENT_ANALYSIS_FILE = ANALYSIS_FILE


load_latest_run_state()


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

def read_analysis(path=None):

    analysis_path = Path(path) if path is not None else ANALYSIS_FILE

    if not analysis_path.exists():
        raise HTTPException(
            status_code=404,
            detail=(
                "analysis.json not found. "
                "Run an analysis first."
            )
        )

    try:

        with open(
            analysis_path,
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

    load_latest_run_state()
    if CURRENT_ANALYSIS_FILE is None:
        raise HTTPException(status_code=404, detail="No completed analysis is available.")
    return read_analysis(CURRENT_ANALYSIS_FILE)


# ============================================================
# AUTOMATIC CAPTURE + TEST + ANALYSIS
# ============================================================

@app.post("/api/start-capture")
def start_capture(pause_seconds: str | None = Query(default=None)):

    global CURRENT_PCAP_FILE, CURRENT_ANALYSIS_FILE

    run_id = f"{time.strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"
    pcap_file = CAPTURE_DIR / f"tcp_zero_window_{run_id}.pcapng"
    analysis_file = RESULTS_DIR / f"analysis_{run_id}.json"

    run_lock_file = acquire_run_lock()
    if run_lock_file is None:
        raise HTTPException(status_code=409, detail="A capture and analysis run is already in progress.")

    CURRENT_PCAP_FILE = None
    CURRENT_ANALYSIS_FILE = None
    if pause_seconds is None:
        pause_schedule, scenario_index = next_pause_schedule()
    else:
        if isinstance(pause_seconds, str) and ',' in pause_seconds:
            pause_schedule = tuple(float(x.strip()) for x in pause_seconds.split(','))
        else:
            # Single value: expand to two varied pauses averaging the target
            # e.g., 15 -> (12, 18), 10 -> (8, 12), 5 -> (4, 6)
            target = float(pause_seconds)
            variation = target * 0.2  # ±20%
            pause1 = round(target - variation + random.random() * variation * 2, 1)
            pause2 = round(target - variation + random.random() * variation * 2, 1)
            # Ensure minimum 0.1s
            pause1 = max(0.1, pause1)
            pause2 = max(0.1, pause2)
            pause_schedule = (pause1, pause2)
        scenario_index = None
    save_run_state("running", run_id)

    dumpcap_path = find_dumpcap()

    if dumpcap_path is None:

        save_run_state("failed", run_id)
        release_run_lock(run_lock_file)

        raise HTTPException(
            status_code=500,
            detail=(
                "dumpcap.exe was not found.\n"
                "Expected location:\n"
                "C:\\Program Files\\Wireshark\\dumpcap.exe"
            )
        )

    if not ANALYZER_FILE.exists():

        save_run_state("failed", run_id)
        release_run_lock(run_lock_file)

        raise HTTPException(
            status_code=404,
            detail="analyzer.py not found."
        )

    if not SENDER_FILE.exists():

        save_run_state("failed", run_id)
        release_run_lock(run_lock_file)

        raise HTTPException(
            status_code=404,
            detail="sender.py not found."
        )

    if not RECEIVER_FILE.exists():

        save_run_state("failed", run_id)
        release_run_lock(run_lock_file)

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
        capture_start_time = time.time()
        # ----------------------------------------------------
        # START DUMPCAP
        # ----------------------------------------------------

        print()
        print("========================================")
        print("       TCP-ZeroGuard AUTOMATIC TEST")
        print("========================================")
        print()
        print(f"Test ID (run_id)       : {run_id}")
        print(f"Pause schedule (sec)   : {list(pause_schedule)}")
        print(f"Scenario index         : {scenario_index}")
        print(f"PCAP output file       : {pcap_file}")
        print(f"Analysis output file   : {analysis_file}")

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
        print(pcap_file)

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
                str(pcap_file),

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
        print(f"Capture started at       : {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(capture_start_time))}")

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
                str(RECEIVER_FILE),
                "--pause-seconds",
                *[str(duration) for duration in pause_schedule]
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

        capture_end_time = time.time()
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
        print(f"Capture ended at         : {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(capture_end_time))}")
        print(f"Capture duration         : {capture_end_time - capture_start_time:.2f} sec")

        # ----------------------------------------------------
        # VERIFY PCAP
        # ----------------------------------------------------

        if not pcap_file.exists():

            raise RuntimeError(
                "Capture finished but the PCAP file "
                "was not created."
            )

        pcap_size = pcap_file.stat().st_size

        if pcap_size <= 24:
            raise RuntimeError("The new PCAP capture is empty; refusing to analyze an old result.")

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
        print(f"Analyzer input PCAP      : {pcap_file}")
        print(f"Analyzer output JSON     : {analysis_file}")

        analyzer_start_time = time.time()
        analyzer_result = subprocess.run(
            [
                sys.executable,
                str(ANALYZER_FILE),
                "--pcap",
                str(pcap_file),
                "--output",
                str(analysis_file)
            ],
            cwd=str(PROJECT_ROOT),
            capture_output=True,
            text=True,
            timeout=120
        )
        analyzer_end_time = time.time()

        if analyzer_result.returncode != 0:

            raise RuntimeError(
                "Analyzer failed.\n\n"
                f"STDOUT:\n"
                f"{analyzer_result.stdout}\n\n"
                f"STDERR:\n"
                f"{analyzer_result.stderr}"
            )

        print(f"Analyzer completed in    : {analyzer_end_time - analyzer_start_time:.2f} sec")

        # ----------------------------------------------------
        # VERIFY ANALYSIS
        # ----------------------------------------------------

        if not analysis_file.exists():

            raise RuntimeError(
                "Analyzer completed but "
                "analysis.json was not generated."
            )

        analysis = read_analysis(analysis_file)
        CURRENT_PCAP_FILE = pcap_file
        CURRENT_ANALYSIS_FILE = analysis_file
        save_run_state("completed", run_id, pcap_file, analysis_file)

        # ----------------------------------------------------
        # FINAL RESULT
        # ----------------------------------------------------

        print()
        print("========================================")
        print("       TCP-ZeroGuard TEST COMPLETE")
        print("========================================")
        print()

        print(
            f"PCAP packets           : "
            f"{analysis.get('capture', {}).get('total_packets', 0)}"
        )

        print(
            f"Zero window packets    : "
            f"{analysis.get('events', {}).get('zero_window_packets', 0)}"
        )

        print(
            f"Stall episodes         : "
            f"{analysis.get('events', {}).get('stall_episodes', 0)}"
        )

        print(
            f"Confirmed probes       : "
            f"{analysis.get('events', {}).get('confirmed_probes', 0)}"
        )

        print(
            f"Probe responses        : "
            f"{analysis.get('events', {}).get('probe_responses', 0)}"
        )

        print(
            f"Recovery episodes      : "
            f"{analysis.get('events', {}).get('recovery_episodes', 0)}"
        )

        print(
            f"Total stall duration   : "
            f"{analysis.get('metrics', {}).get('total_stall_duration_sec', 0):.3f} sec"
        )

        print(
            f"Maximum stall duration : "
            f"{analysis.get('metrics', {}).get('maximum_stall_duration_sec', 0):.3f} sec"
        )

        print(
            f"Average stall duration : "
            f"{analysis.get('metrics', {}).get('average_stall_duration_sec', 0):.3f} sec"
        )

        print()

        return {
            "status": "Automatic capture and analysis completed",
            "capture": {
                "interface": interface,
                "filter": CAPTURE_FILTER,
                "pcap_file": str(pcap_file),
                "pcap_size_bytes": pcap_size,
                "run_id": run_id,
                "pause_seconds": pause_schedule[0],
                "pause_schedule_seconds": list(pause_schedule),
                "scenario_index": scenario_index
            },
            "analysis": analysis,
            "analyzer_output": analyzer_result.stdout
        }

    except HTTPException:

        save_run_state("failed", run_id)

        raise

    except Exception as error:

        save_run_state("failed", run_id)

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

    finally:
        release_run_lock(run_lock_file)


# ============================================================
# MANUAL ANALYZER ENDPOINT
# ============================================================

@app.post("/api/analyze")
def analyze_pcap():

    global CURRENT_ANALYSIS_FILE

    if not ANALYZER_FILE.exists():

        raise HTTPException(
            status_code=404,
            detail="analyzer.py not found."
        )

    run_lock_file = acquire_run_lock()
    if run_lock_file is None:
        raise HTTPException(status_code=409, detail="A capture and analysis run is already in progress.")

    load_latest_run_state()
    if CURRENT_PCAP_FILE is None or not CURRENT_PCAP_FILE.exists():
        release_run_lock(run_lock_file)

        raise HTTPException(
            status_code=404,
            detail=(
                "PCAP file not found: "
                "capture/tcp_zero_window.pcapng"
            )
        )

    pcap_file = CURRENT_PCAP_FILE
    analysis_file = RESULTS_DIR / f"analysis_manual_{time.strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}.json"

    try:

        result = subprocess.run(
            [
                sys.executable,
                str(ANALYZER_FILE),
                "--pcap",
                str(pcap_file),
                "--output",
                str(analysis_file)
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

        analysis = read_analysis(analysis_file)
        CURRENT_ANALYSIS_FILE = analysis_file
        save_run_state(
            "completed",
            f"manual_{uuid.uuid4().hex[:8]}",
            pcap_file,
            analysis_file
        )

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

    finally:
        release_run_lock(run_lock_file)
