# TCP-ZeroGuard

### Live Detection and Analysis of TCP Receive-Window Stalls

TCP-ZeroGuard is a Computer Networks project that detects and analyzes TCP Zero-Window events, Persist Timer probes, probe responses, and window recovery.

## Features

- TCP Zero-Window detection
- Zero-Window Probe detection
- Probe Response detection
- Window Recovery detection
- Stall duration analysis
- Packet-level event timeline
- PCAP/PCAPNG analysis
- Interactive web dashboard

## Technologies

- Python
- Scapy
- Wireshark
- Npcap
- FastAPI
- HTML, CSS, JavaScript

## Project Structure

TCP-ZeroGuard/
├── backend/
│   ├── main.py
│   └── __init__.py
├── frontend/
│   ├── index.html
│   ├── style.css
│   └── script.js
├── capture/
├── results/
├── analyzer.py
├── sender.py
├── receiver.py
└── README.md

## How It Works

TCP Traffic
     ↓
Wireshark / Npcap
     ↓
PCAP Capture
     ↓
Python Analyzer
     ↓
Zero-Window Detection
     ↓
Probe & Response Detection
     ↓
Recovery Detection
     ↓
Web Dashboard

