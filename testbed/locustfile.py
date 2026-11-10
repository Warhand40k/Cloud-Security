"""
Locust Load Generation File for Stage 3 Testbed (Benign Diurnal Load)
Simulates realistic e-commerce user behavior with a diurnal (day/night) traffic shape.
"""

import math
import random
from locust import HttpUser, task, between, LoadTestShape

class ECommerceUser(HttpUser):
    wait_time = between(0.1, 0.5)

    @task(5)
    def view_catalog(self):
        limit = random.choice([10, 20, 50])
        self.client.get(f"/api/catalog?limit={limit}", name="/api/catalog")

    @task(3)
    def view_item(self):
        item_id = random.randint(1, 100)
        self.client.get(f"/api/catalog/{item_id}", name="/api/catalog/:id")

    @task(2)
    def search_products(self):
        query = random.choice(["Cloud", "Component", "1", "5", "8", "10"])
        self.client.get(f"/api/search?q={query}", name="/api/search")

    @task(1)
    def checkout(self):
        payload = {
            "cart_id": f"CART-{random.randint(1000, 9999)}",
            "items": [{"id": random.randint(1, 100), "qty": random.randint(1, 3)}]
        }
        self.client.post("/api/checkout", json=payload, name="/api/checkout")

    @task(1)
    def health_check(self):
        self.client.get("/health", name="/health")

class DiurnalLoadShape(LoadTestShape):
    """
    Sinusoidal diurnal traffic pattern:
    Generates realistic diurnal cycles with daytime peaks and nighttime troughs.
    """
    total_duration_sec = 600  # 10 minutes total for 600 windows in accelerated testbed
    base_users = 20
    peak_users = 80

    def tick(self):
        run_time = self.get_run_time()
        if run_time > self.total_duration_sec:
            return None

        # Sinusoidal cycle: sin(2 * pi * t / T)
        cycle_progress = (run_time / self.total_duration_sec) * 2.0 * math.pi
        sin_val = math.sin(cycle_progress)  # between -1 and 1

        # Map to users
        target_users = int(self.base_users + (self.peak_users - self.base_users) * (0.5 * (sin_val + 1.0)))
        target_users = max(5, target_users + random.randint(-2, 2))
        spawn_rate = 10

        return (target_users, spawn_rate)
