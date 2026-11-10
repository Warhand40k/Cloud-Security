"""
Campaign Schedule Definition for Stage 3 Testbed Validation
Defines 25 labeled campaigns across 600 sixty-second windows (10 hours total).
- Windows 0 - 199: Pure Benign Training Slice (N=200, diurnal baseline)
- Windows 200 - 299: Held-Out Benign Validation Slice (N=100, threshold calibration)
- Windows 300 - 599: Held-Out Test Evaluation Slice (N=300) containing 25 labeled campaigns

Campaign Categories (25 total):
1. Volumetric HTTP Floods (5 campaigns): Sustained floods overwhelming request rate
2. Low-and-Slow / Slowloris (5 campaigns): High active connections, low rate, elevated p99 latency
3. Intermittent / Pulsing Spikes (5 campaigns): On/off burst patterns testing window aggregation
4. Endpoint Reconnaissance Scanning (5 campaigns): Directory traversal/probing with 404/400 cascades
5. Benign Flash Crowds (5 campaigns): High volume of valid catalog requests (200 OK, Label=0)
"""

from typing import List, Dict, Any

def get_campaign_schedule() -> List[Dict[str, Any]]:
    campaigns = [
        # --- Category 1: Volumetric Floods (Label = 1) ---
        {
            "id": 1,
            "type": "volumetric_flood",
            "shape": "sustained_rectangular",
            "start_window": 310,
            "end_window": 316,
            "is_attack": 1,
            "is_flash_crowd": 0,
            "description": "High-rate GET flood targeting /api/catalog",
            "intensity": 5.0  # multiplier over baseline load
        },
        {
            "id": 2,
            "type": "volumetric_flood",
            "shape": "rapid_triangular_ramp",
            "start_window": 325,
            "end_window": 330,
            "is_attack": 1,
            "is_flash_crowd": 0,
            "description": "Rapid ramp-up POST flood on /api/checkout",
            "intensity": 6.0
        },
        {
            "id": 3,
            "type": "volumetric_flood",
            "shape": "trapezoidal_surge",
            "start_window": 340,
            "end_window": 348,
            "is_attack": 1,
            "is_flash_crowd": 0,
            "description": "Trapezoidal flood hitting root and catalog endpoints",
            "intensity": 4.5
        },
        {
            "id": 4,
            "type": "volumetric_flood",
            "shape": "pulsing_flood",
            "start_window": 355,
            "end_window": 362,
            "is_attack": 1,
            "is_flash_crowd": 0,
            "description": "Heavy search endpoint volumetric exhaustion",
            "intensity": 5.5
        },
        {
            "id": 5,
            "type": "volumetric_flood",
            "shape": "sustained_heavy",
            "start_window": 370,
            "end_window": 379,
            "is_attack": 1,
            "is_flash_crowd": 0,
            "description": "Sustained 10-minute multi-endpoint flood",
            "intensity": 7.0
        },

        # --- Category 2: Low-and-Slow / Slowloris (Label = 1) ---
        {
            "id": 6,
            "type": "slowloris",
            "shape": "constant_connection_hold",
            "start_window": 385,
            "end_window": 392,
            "is_attack": 1,
            "is_flash_crowd": 0,
            "description": "Slowloris header exhaustion holding connections open",
            "intensity": 1.2
        },
        {
            "id": 7,
            "type": "slowloris",
            "shape": "slow_read_dos",
            "start_window": 400,
            "end_window": 406,
            "is_attack": 1,
            "is_flash_crowd": 0,
            "description": "Slow-read attack starving response buffers",
            "intensity": 1.3
        },
        {
            "id": 8,
            "type": "slowloris",
            "shape": "intermittent_slowloris",
            "start_window": 412,
            "end_window": 418,
            "is_attack": 1,
            "is_flash_crowd": 0,
            "description": "Intermittent slowloris connection pooling attack",
            "intensity": 1.4
        },
        {
            "id": 9,
            "type": "slowloris",
            "shape": "post_slowloris",
            "start_window": 424,
            "end_window": 430,
            "is_attack": 1,
            "is_flash_crowd": 0,
            "description": "Slow body POST transmission on /api/checkout",
            "intensity": 1.3
        },
        {
            "id": 10,
            "type": "slowloris",
            "shape": "stealth_connection_hold",
            "start_window": 435,
            "end_window": 441,
            "is_attack": 1,
            "is_flash_crowd": 0,
            "description": "Stealth connection hold below standard timeout thresholds",
            "intensity": 1.2
        },

        # --- Category 3: Intermittent / Pulsing Spikes (Label = 1) ---
        {
            "id": 11,
            "type": "intermittent_spike",
            "shape": "periodic_burst",
            "start_window": 448,
            "end_window": 453,
            "is_attack": 1,
            "is_flash_crowd": 0,
            "description": "30-second on / 30-second off intermittent pulsing spike",
            "intensity": 4.0
        },
        {
            "id": 12,
            "type": "intermittent_spike",
            "shape": "dual_pulse",
            "start_window": 458,
            "end_window": 462,
            "is_attack": 1,
            "is_flash_crowd": 0,
            "description": "Twin rapid micro-burst attacks",
            "intensity": 4.5
        },
        {
            "id": 13,
            "type": "intermittent_spike",
            "shape": "staccato_spike",
            "start_window": 468,
            "end_window": 472,
            "is_attack": 1,
            "is_flash_crowd": 0,
            "description": "Short staccato probe burst",
            "intensity": 3.8
        },
        {
            "id": 14,
            "type": "intermittent_spike",
            "shape": "oscillating_spike",
            "start_window": 477,
            "end_window": 483,
            "is_attack": 1,
            "is_flash_crowd": 0,
            "description": "Oscillating frequency burst across 6 windows",
            "intensity": 4.2
        },
        {
            "id": 15,
            "type": "intermittent_spike",
            "shape": "decaying_burst",
            "start_window": 488,
            "end_window": 493,
            "is_attack": 1,
            "is_flash_crowd": 0,
            "description": "Decaying burst attack testing persistence recovery",
            "intensity": 3.5
        },

        # --- Category 4: Endpoint Reconnaissance / Scanning (Label = 1) ---
        {
            "id": 16,
            "type": "endpoint_recon",
            "shape": "directory_brute_force",
            "start_window": 498,
            "end_window": 504,
            "is_attack": 1,
            "is_flash_crowd": 0,
            "description": "Directory brute-force scanning (/admin, /.env, /config)",
            "intensity": 3.0
        },
        {
            "id": 17,
            "type": "endpoint_recon",
            "shape": "catalog_id_enumeration",
            "start_window": 510,
            "end_window": 515,
            "is_attack": 1,
            "is_flash_crowd": 0,
            "description": "Catalog ID out-of-range enumeration attack",
            "intensity": 2.8
        },
        {
            "id": 18,
            "type": "endpoint_recon",
            "shape": "api_fuzzing",
            "start_window": 520,
            "end_window": 525,
            "is_attack": 1,
            "is_flash_crowd": 0,
            "description": "Malformed JSON payload fuzzing on /api/checkout (400 errors)",
            "intensity": 2.5
        },
        {
            "id": 19,
            "type": "endpoint_recon",
            "shape": "vulnerability_sweep",
            "start_window": 530,
            "end_window": 535,
            "is_attack": 1,
            "is_flash_crowd": 0,
            "description": "Automated web vulnerability scanner signatures sweep",
            "intensity": 3.2
        },
        {
            "id": 20,
            "type": "endpoint_recon",
            "shape": "rapid_recon_sweep",
            "start_window": 540,
            "end_window": 545,
            "is_attack": 1,
            "is_flash_crowd": 0,
            "description": "Rapid endpoint existence check triggering 404 cascades",
            "intensity": 3.0
        },

        # --- Category 5: Benign Flash Crowds (Label = 0; Critical Test) ---
        {
            "id": 21,
            "type": "flash_crowd",
            "shape": "breaking_promotion_surge",
            "start_window": 550,
            "end_window": 556,
            "is_attack": 0,  # Legitimate user surge!
            "is_flash_crowd": 1,
            "description": "Breaking sale promotion: 4x legitimate surge to /api/catalog (all 200 OK)",
            "intensity": 4.0
        },
        {
            "id": 22,
            "type": "flash_crowd",
            "shape": "viral_social_surge",
            "start_window": 560,
            "end_window": 566,
            "is_attack": 0,
            "is_flash_crowd": 1,
            "description": "Viral social media product link: legitimate search & catalog views",
            "intensity": 4.5
        },
        {
            "id": 23,
            "type": "flash_crowd",
            "shape": "morning_traffic_surge",
            "start_window": 570,
            "end_window": 575,
            "is_attack": 0,
            "is_flash_crowd": 1,
            "description": "Morning opening business surge with legitimate checkouts",
            "intensity": 3.5
        },
        {
            "id": 24,
            "type": "flash_crowd",
            "shape": "flash_sale_spike",
            "start_window": 580,
            "end_window": 586,
            "is_attack": 0,
            "is_flash_crowd": 1,
            "description": "Limited flash-sale: heavy legitimate catalog traffic with valid responses",
            "intensity": 5.0
        },
        {
            "id": 25,
            "type": "flash_crowd",
            "shape": "evening_peak_surge",
            "start_window": 590,
            "end_window": 597,
            "is_attack": 0,
            "is_flash_crowd": 1,
            "description": "Evening peak browsing surge across all legitimate endpoints",
            "intensity": 4.2
        }
    ]
    return campaigns
