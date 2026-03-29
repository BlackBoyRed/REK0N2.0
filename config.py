import os
from dotenv import load_dotenv

load_dotenv()

# ── API Keys ──────────────────────────────────────────────────────────────────
SHODAN_API_KEY   = os.getenv("SHODAN_API_KEY", "")
GITHUB_TOKEN     = os.getenv("GITHUB_TOKEN", "")

# ── Scan settings ─────────────────────────────────────────────────────────────
class ScanMode:
    STEALTH    = "stealth"     # passive only, no direct target contact
    NORMAL     = "normal"      # passive + active, default timings
    AGGRESSIVE = "aggressive"  # everything, fast scans

DEFAULT_MODE = ScanMode.NORMAL

NMAP_TIMING = {
    ScanMode.STEALTH:    "-T2",
    ScanMode.NORMAL:     "-T4",
    ScanMode.AGGRESSIVE: "-T5",
}

# ── Tool paths ────────────────────────────────────────────────────────────────
SUBLIST3R_PATH   = os.getenv("SUBLIST3R_PATH", "sublist3r")
GOBUSTER_PATH    = os.getenv("GOBUSTER_PATH", "gobuster")
WHATWEB_PATH     = os.getenv("WHATWEB_PATH", "whatweb")
WORDLIST_PATH    = os.getenv("WORDLIST_PATH", "/usr/share/wordlists/dirb/common.txt")

# ── Timeouts (seconds) ────────────────────────────────────────────────────────
TIMEOUT_PASSIVE  = 30
TIMEOUT_NMAP     = 300
TIMEOUT_SUBLIST3R= 180
TIMEOUT_GOBUSTER = 300
TIMEOUT_WHATWEB  = 60

# ── Output ────────────────────────────────────────────────────────────────────
RAW_DATA_DIR     = os.path.join(os.path.dirname(__file__), "data", "raw")
REPORTS_DIR      = os.path.join(os.path.dirname(__file__), "reports")

# ── Model ─────────────────────────────────────────────────────────────────────
MODEL_BASE       = "unsloth/llama-3.1-8b"
MODEL_FINETUNED  = os.path.join(os.path.dirname(__file__), "model", "finetuned")
INFERENCE_URL    = os.getenv("INFERENCE_URL", "http://localhost:11434")  # Ollama default
