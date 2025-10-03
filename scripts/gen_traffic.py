#!/usr/bin/env python3
import requests, time

TARGET = "http://127.0.0.1:8080"  # Change to your target web server

for i in range(50):
    # Normal traffic
    requests.get(f"{TARGET}/?q=normal{i}")
    # Malicious traffic triggers the IDS rule
    if i % 10 == 0:
        requests.get(f"{TARGET}/?q=eviltest_{i}")
    time.sleep(0.1)

print("Traffic generation complete")
