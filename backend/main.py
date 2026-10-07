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
from datetime import datetime
from io import BytesIO
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse

try:
    import msvcrt
except ImportError:
    msvcrt = None
    import fcntl

# PDF generation
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.colors import HexColor
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
    HRFlowable
)


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


# ============================================================
# PDF REPORT DOWNLOAD
# ============================================================

@app.get("/api/report/pdf")
def download_pdf_report():
    """
    Generate and return a PDF report based on the current analysis results.
    Uses the same analysis data that the dashboard displays.
    """
    load_latest_run_state()
    if CURRENT_ANALYSIS_FILE is None or not CURRENT_ANALYSIS_FILE.exists():
        raise HTTPException(
            status_code=404,
            detail="No completed analysis available. Run an analysis first."
        )

    try:
        analysis = read_analysis(CURRENT_ANALYSIS_FILE)
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to read analysis data: {e}"
        )

    # Generate PDF
    buffer = BytesIO()
    try:
        doc = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            rightMargin=50,
            leftMargin=50,
            topMargin=50,
            bottomMargin=50
        )

        styles = getSampleStyleSheet()
        story = []

        # Custom styles
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=22,
            textColor=HexColor('#1a1a2e'),
            spaceAfter=6,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        )

        subtitle_style = ParagraphStyle(
            'CustomSubtitle',
            parent=styles['Normal'],
            fontSize=11,
            textColor=HexColor('#666666'),
            spaceAfter=20,
            alignment=TA_CENTER,
        )

        section_style = ParagraphStyle(
            'SectionHeader',
            parent=styles['Heading2'],
            fontSize=14,
            textColor=HexColor('#00b4d8'),
            spaceBefore=18,
            spaceAfter=10,
            fontName='Helvetica-Bold',
            borderWidth=0,
            borderPadding=0,
        )

        subsection_style = ParagraphStyle(
            'SubsectionHeader',
            parent=styles['Heading3'],
            fontSize=11,
            textColor=HexColor('#333333'),
            spaceBefore=10,
            spaceAfter=6,
            fontName='Helvetica-Bold',
        )

        body_style = ParagraphStyle(
            'CustomBody',
            parent=styles['Normal'],
            fontSize=10,
            textColor=HexColor('#333333'),
            spaceAfter=4,
            leading=14,
        )

        label_style = ParagraphStyle(
            'LabelStyle',
            parent=styles['Normal'],
            fontSize=10,
            textColor=HexColor('#555555'),
            fontName='Helvetica-Bold',
        )

        value_style = ParagraphStyle(
            'ValueStyle',
            parent=styles['Normal'],
            fontSize=10,
            textColor=HexColor('#222222'),
        )

        status_colors = {
            'HEALTHY': '#2ecc71',
            'RECOVERED': '#00b4d8',
            'CURRENTLY STALLED': '#e74c3c',
            'STALL DETECTED (UNRESOLVED)': '#f39c12',
            'UNKNOWN': '#95a5a6',
        }

        # ============ TITLE ============
        story.append(Paragraph("TCP-ZeroGuard Analysis Report", title_style))
        story.append(Paragraph(
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            subtitle_style
        ))
        story.append(HRFlowable(width="100%", thickness=2, color=HexColor('#00b4d8'), spaceAfter=20))

        # ============ 1. CAPTURE INFORMATION ============
        story.append(Paragraph("1. Capture Information", section_style))

        capture = analysis.get('capture', {})
        pcap_file = analysis.get('capture', {}).get('total_packets', 'N/A')
        pcap_filename = Path(CURRENT_ANALYSIS_FILE).stem.replace('analysis_', 'tcp_zero_window_') + '.pcapng'

        capture_data = [
            ['Field', 'Value'],
            ['PCAP Filename', pcap_filename],
            ['Total Packets', str(capture.get('total_packets', 'N/A'))],
            ['TCP Packets', str(capture.get('tcp_packets', 'N/A'))],
            ['Analyzer', 'TCP-ZeroGuard'],
            ['Analysis Status', 'Completed'],
            ['Report Generated', datetime.now().strftime('%Y-%m-%d %H:%M:%S')],
        ]

        capture_table = Table(capture_data, colWidths=[2.2*inch, 4*inch])
        capture_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), HexColor('#00b4d8')),
            ('TEXTCOLOR', (0, 0), (-1, 0), HexColor('#ffffff')),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('BACKGROUND', (0, 1), (-1, -1), HexColor('#f8f9fa')),
            ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#dee2e6')),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('FONTNAME', (0, 1), (0, -1), 'Helvetica-Bold'),
        ]))
        story.append(capture_table)
        story.append(Spacer(1, 16))

        # ============ 2. TCP METRICS ============
        story.append(Paragraph("2. TCP Metrics", section_style))

        metrics = analysis.get('metrics', {})
        events = analysis.get('events', {})

        metrics_data = [
            ['Metric', 'Value'],
            ['Zero Window Packets', str(events.get('zero_window_packets', 0))],
            ['Stall Episodes', str(events.get('stall_episodes', 0))],
            ['Zero Window Probes', str(events.get('confirmed_probes', 0))],
            ['Probe Responses', str(events.get('probe_responses', 0))],
            ['Recovery Episodes', str(events.get('recovery_episodes', 0))],
            ['Total Stall Duration', f"{metrics.get('total_stall_duration_sec', 0):.3f} s"],
            ['Maximum Stall Duration', f"{metrics.get('maximum_stall_duration_sec', 0):.3f} s"],
            ['Average Stall Duration', f"{metrics.get('average_stall_duration_sec', 0):.3f} s"],
        ]

        metrics_table = Table(metrics_data, colWidths=[2.8*inch, 3.4*inch])
        metrics_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), HexColor('#00b4d8')),
            ('TEXTCOLOR', (0, 0), (-1, 0), HexColor('#ffffff')),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('BACKGROUND', (0, 1), (-1, -1), HexColor('#f8f9fa')),
            ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#dee2e6')),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('FONTNAME', (0, 1), (0, -1), 'Helvetica-Bold'),
        ]))
        story.append(metrics_table)
        story.append(Spacer(1, 16))

        # ============ 3. ROOT CAUSE ANALYSIS ============
        story.append(Paragraph("3. Root Cause Analysis", section_style))

        root_cause = analysis.get('root_cause_analysis', {})
        if root_cause:
            status = root_cause.get('status', 'UNKNOWN')
            status_color = status_colors.get(status, '#95a5a6')

            rc_data = [
                ['Field', 'Details'],
                ['Status', status],
                ['Likely Cause', root_cause.get('likely_cause', 'N/A')],
                ['Explanation', root_cause.get('explanation', 'N/A')],
                ['Impact', root_cause.get('impact', 'N/A')],
                ['Recommendation', root_cause.get('recommendation', 'N/A')],
            ]

            rc_table = Table(rc_data, colWidths=[1.8*inch, 4.4*inch])
            rc_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), HexColor('#00b4d8')),
                ('TEXTCOLOR', (0, 0), (-1, 0), HexColor('#ffffff')),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                ('TOPPADDING', (0, 0), (-1, -1), 8),
                ('BACKGROUND', (0, 1), (0, -1), HexColor('#f8f9fa')),
                ('BACKGROUND', (1, 1), (1, 1), HexColor(status_color + '20')),
                ('TEXTCOLOR', (1, 1), (1, 1), HexColor(status_color)),
                ('FONTNAME', (1, 1), (1, 1), 'Helvetica-Bold'),
                ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#dee2e6')),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('FONTNAME', (0, 1), (0, -1), 'Helvetica-Bold'),
            ]))
            story.append(rc_table)
        else:
            story.append(Paragraph("Root cause analysis not available in this analysis.", body_style))
        story.append(Spacer(1, 16))

        # ============ 4. IMPORTANT EVENT TIMELINE ============
        story.append(Paragraph("4. Important Event Timeline", section_style))

        timeline = analysis.get('timeline', [])
        event_rows = [['Packet', 'Event', 'Window', 'Sequence', 'ACK', 'Payload', 'Timing']]

        # Filter for important events only
        important_events = ['ZERO_WINDOW_START', 'ZERO_WINDOW_PROBE', 'PROBE_RESPONSE', 'WINDOW_REOPENED']
        event_count = 0
        for event in timeline:
            if event.get('event') in important_events and event_count < 30:
                event_name_map = {
                    'ZERO_WINDOW_START': 'Zero Window Start',
                    'ZERO_WINDOW_PROBE': 'Zero Window Probe',
                    'PROBE_RESPONSE': 'Probe Response',
                    'WINDOW_REOPENED': 'Window Reopened',
                }
                timing = ''
                if event.get('event') == 'ZERO_WINDOW_START' and event.get('stall_duration') is not None:
                    timing = f"Stall: {event['stall_duration']:.3f}s"
                elif event.get('event') == 'ZERO_WINDOW_PROBE' and event.get('probe_interval_sec') is not None:
                    timing = f"Interval: {event['probe_interval_sec']:.3f}s"
                elif event.get('event') == 'PROBE_RESPONSE' and event.get('probe_response_latency_sec') is not None:
                    timing = f"Latency: {event['probe_response_latency_sec']*1000:.2f}ms"
                elif event.get('event') == 'WINDOW_REOPENED' and event.get('stall_duration') is not None:
                    timing = f"Stall: {event['stall_duration']:.3f}s"

                event_rows.append([
                    str(event.get('packet', 'N/A')),
                    event_name_map.get(event.get('event'), event.get('event', 'N/A')),
                    str(event.get('window', 'N/A')),
                    str(event.get('seq', 'N/A')),
                    str(event.get('ack', 'N/A')),
                    f"{event.get('payload_length', 0)} bytes",
                    timing,
                ])
                event_count += 1

        if event_count == 0:
            event_rows.append(['—', 'No significant events recorded', '—', '—', '—', '—', '—'])

        event_table = Table(event_rows, colWidths=[0.5*inch, 1.1*inch, 0.6*inch, 1.0*inch, 1.0*inch, 0.7*inch, 1.3*inch])
        event_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), HexColor('#00b4d8')),
            ('TEXTCOLOR', (0, 0), (-1, 0), HexColor('#ffffff')),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BACKGROUND', (0, 1), (-1, -1), HexColor('#f8f9fa')),
            ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#dee2e6')),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('FONTSIZE', (0, 1), (-1, -1), 8),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [HexColor('#ffffff'), HexColor('#f8f9fa')]),
        ]))
        story.append(event_table)
        story.append(Spacer(1, 20))

        # Footer
        story.append(HRFlowable(width="100%", thickness=1, color=HexColor('#dee2e6'), spaceAfter=10))
        story.append(Paragraph(
            "TCP-ZeroGuard — TCP Receive-Window Stall Detection & Analysis",
            ParagraphStyle('Footer', parent=styles['Normal'], fontSize=8, textColor=HexColor('#999999'), alignment=TA_CENTER)
        ))

        doc.build(story)
        buffer.seek(0)

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to generate PDF report: {e}"
        )

    # Return PDF as streaming response
    timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
    filename = f"TCP-ZeroGuard-Report-{timestamp}.pdf"

    return StreamingResponse(
        BytesIO(buffer.read()),
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )
