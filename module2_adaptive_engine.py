"""
Module 2: Adaptive Security Engine
====================================
Reads real-time hardware metrics (CPU%, RAM, Battery)
and classifies the system into a security profile:
  - LOW    → constrained device, prioritise efficiency
  - MEDIUM → balanced device
  - HIGH   → powerful device, maximise security

Output: SecurityProfile dataclass consumed by Modules 3, 4, and 5.
"""

import psutil
import platform
from dataclasses import dataclass
from typing import Literal
import time


# ─────────────────────────────────────────────
# 1.  Data Structures
# ─────────────────────────────────────────────

SecurityLevel = Literal["LOW", "MEDIUM", "HIGH"]


@dataclass
class HardwareSnapshot:
    """Raw hardware readings captured at a single moment."""
    cpu_percent: float          # 0–100 %
    ram_available_mb: float     # MB of free RAM
    battery_percent: float      # 0–100 % (100 if no battery / desktop)
    on_power: bool              # True if plugged in or no battery


@dataclass
class SecurityProfile:
    """
    Downstream configuration produced by the Adaptive Security Engine.
    Every other module reads from this object — do NOT hardcode values.
    """
    level: SecurityLevel

    # ── For Module 3 (chaos selection) ──────────
    chaos_model: str            # "henon" | "lorenz" | "chen" | "rossler"
    chaos_iterations: int       # warm-up + production iterations

    # ── For Module 4 (HKDF) ─────────────────────
    hkdf_hash: str              # "sha256" | "sha384" | "sha512"
    hkdf_length: int            # derived key length in bytes (32 / 48 / 64)

    # ── For Module 5 (AES-256-GCM) ──────────────
    aes_tag_length: int         # GCM authentication tag bytes (12 / 14 / 16)
    aes_nonce_length: int       # nonce / IV bytes (12 standard for GCM)

    # ── Human-readable summary ───────────────────
    rationale: str              # why this profile was chosen


# ─────────────────────────────────────────────
# 2.  Hardware Sampler
# ─────────────────────────────────────────────

def _sample_hardware(cpu_interval: float = 1.0) -> HardwareSnapshot:
    """
    Capture a single hardware snapshot.

    Parameters
    ----------
    cpu_interval : float
        Seconds over which psutil averages CPU usage.
        1.0 s gives a stable reading without being too slow.
    """
    cpu = psutil.cpu_percent(interval=cpu_interval)

    ram_info = psutil.virtual_memory()
    ram_available_mb = ram_info.available / (1024 ** 2)

    battery = psutil.sensors_battery()
    if battery is None:
        # Desktop or system with no battery sensor → treat as fully charged & plugged in
        battery_percent = 100.0
        on_power = True
    else:
        battery_percent = battery.percent
        on_power = battery.power_plugged

    return HardwareSnapshot(
        cpu_percent=cpu,
        ram_available_mb=ram_available_mb,
        battery_percent=battery_percent,
        on_power=on_power,
    )


# ─────────────────────────────────────────────
# 3.  Scoring & Classification Logic
# ─────────────────────────────────────────────

def _compute_resource_score(snap: HardwareSnapshot) -> float:
    """
    Produce a single 0–100 'resource availability' score.

    Higher score  →  device has plenty of resources  →  HIGH profile
    Lower  score  →  device is constrained            →  LOW  profile

    Weighting rationale
    -------------------
    CPU    (40 %) : inverted — high CPU usage means LESS resource available
    RAM    (35 %) : normalised against a 4 GB reference ceiling
    Battery(25 %) : low battery on unplugged device penalises score heavily
    """

    # CPU score: 100 when idle, 0 when fully loaded
    cpu_score = max(0.0, 100.0 - snap.cpu_percent)

    # RAM score: 100 when ≥ 4 GB free, scales linearly down to 0
    RAM_CEILING_MB = 4096.0
    ram_score = min(snap.ram_available_mb / RAM_CEILING_MB, 1.0) * 100.0

    # Battery score
    if snap.on_power:
        # Plugged in → battery is not a constraint
        battery_score = 100.0
    else:
        # On battery → penalise if low
        battery_score = snap.battery_percent  # already 0–100

    weighted = (
        0.40 * cpu_score +
        0.35 * ram_score +
        0.25 * battery_score
    )
    return round(weighted, 2)


def _score_to_level(score: float) -> SecurityLevel:
    """
    Map resource score → security level.

    Thresholds (tunable):
      score < 35   →  LOW    (save resources, lighter crypto)
      35 ≤ score < 65 →  MEDIUM (balanced)
      score ≥ 65   →  HIGH   (full security, heavier crypto)
    """
    if score < 35.0:
        return "LOW"
    elif score < 65.0:
        return "MEDIUM"
    else:
        return "HIGH"


# ─────────────────────────────────────────────
# 4.  Profile Builder
# ─────────────────────────────────────────────

# Profile configuration table
# Each level maps to concrete crypto parameters
_PROFILE_TABLE: dict[SecurityLevel, dict] = {
    "LOW": {
        "chaos_model":      "henon",        # 2D map — cheapest to compute
        "chaos_iterations": 5_000,
        "hkdf_hash":        "sha256",
        "hkdf_length":      32,             # 256-bit key
        "aes_tag_length":   12,             # 96-bit GCM tag (minimum secure)
        "aes_nonce_length": 12,
    },
    "MEDIUM": {
        "chaos_model":      "lorenz",       # 3D ODE — moderate cost
        "chaos_iterations": 50_000,
        "hkdf_hash":        "sha384",
        "hkdf_length":      48,             # 384-bit key (HKDF output, AES still 256)
        "aes_tag_length":   14,             # 112-bit GCM tag
        "aes_nonce_length": 12,
    },
    "HIGH": {
        "chaos_model":      "chen",         # 3D ODE with stronger nonlinearity
        "chaos_iterations": 200_000,
        "hkdf_hash":        "sha512",
        "hkdf_length":      64,             # 512-bit key material (HKDF), AES uses 256
        "aes_tag_length":   16,             # 128-bit GCM tag (maximum)
        "aes_nonce_length": 12,
    },
}


def _build_profile(level: SecurityLevel, snap: HardwareSnapshot, score: float) -> SecurityProfile:
    cfg = _PROFILE_TABLE[level]
    rationale = (
        f"Resource score {score}/100 → {level} profile | "
        f"CPU {snap.cpu_percent:.1f}% | "
        f"RAM free {snap.ram_available_mb:.0f} MB | "
        f"Battery {snap.battery_percent:.0f}% "
        f"({'plugged in' if snap.on_power else 'on battery'})"
    )
    return SecurityProfile(
        level=level,
        chaos_model=cfg["chaos_model"],
        chaos_iterations=cfg["chaos_iterations"],
        hkdf_hash=cfg["hkdf_hash"],
        hkdf_length=cfg["hkdf_length"],
        aes_tag_length=cfg["aes_tag_length"],
        aes_nonce_length=cfg["aes_nonce_length"],
        rationale=rationale,
    )


# ─────────────────────────────────────────────
# 5.  Public API
# ─────────────────────────────────────────────

def run_adaptive_engine(
    cpu_interval: float = 1.0,
    verbose: bool = True,
) -> SecurityProfile:
    """
    Main entry point for Module 2.

    Usage (from any other module)
    ------------------------------
        from module2_adaptive_engine import run_adaptive_engine
        profile = run_adaptive_engine()
        print(profile.level)           # "LOW" | "MEDIUM" | "HIGH"
        print(profile.chaos_model)     # passed to Module 3
        print(profile.aes_tag_length)  # passed to Module 5

    Parameters
    ----------
    cpu_interval : float
        Seconds to average CPU reading (default 1 s).
    verbose : bool
        Print a human-readable summary table to stdout.

    Returns
    -------
    SecurityProfile
        Fully populated profile dataclass.
    """
    if verbose:
        print("\n" + "═" * 55)
        print("   MODULE 2 — ADAPTIVE SECURITY ENGINE")
        print("═" * 55)
        print("  Sampling hardware metrics …", end="", flush=True)

    snap = _sample_hardware(cpu_interval=cpu_interval)
    score = _compute_resource_score(snap)
    level = _score_to_level(score)
    profile = _build_profile(level, snap, score)

    if verbose:
        print(" done.\n")
        print(f"  {'Metric':<25} {'Value':>15}")
        print("  " + "─" * 42)
        print(f"  {'CPU Usage':<25} {snap.cpu_percent:>14.1f}%")
        print(f"  {'RAM Available':<25} {snap.ram_available_mb:>11.0f} MB")
        print(f"  {'Battery':<25} {snap.battery_percent:>14.0f}%")
        print(f"  {'On Power':<25} {str(snap.on_power):>15}")
        print(f"  {'Resource Score':<25} {score:>14.2f}")
        print()
        print(f"  ▶  Security Level   : {level}")
        print(f"  ▶  Chaos Model      : {profile.chaos_model}")
        print(f"  ▶  Chaos Iterations : {profile.chaos_iterations:,}")
        print(f"  ▶  HKDF Hash        : {profile.hkdf_hash.upper()}")
        print(f"  ▶  HKDF Key Length  : {profile.hkdf_length * 8} bits")
        print(f"  ▶  AES GCM Tag      : {profile.aes_tag_length * 8} bits")
        print(f"  ▶  AES Nonce        : {profile.aes_nonce_length * 8} bits")
        print()
        print(f"  Rationale: {profile.rationale}")
        print("═" * 55 + "\n")

    return profile


# ─────────────────────────────────────────────
# 6.  Allow direct run for quick demo
# ─────────────────────────────────────────────

if __name__ == "__main__":
    profile = run_adaptive_engine(verbose=True)
