import os
from src.wrappers.base_wrapper import BaseWrapper, stable_artifact_id

SUSPICIOUS_DOMAINS = [
    "bit.ly", "tinyurl", "grabify",
    "phishing", "login-secure", "verify-account"
]

class BrowserWrapper(BaseWrapper):
    consumes = "browser"

    def __init__(self):
        super().__init__("browser")

    def run(self, history_file: str) -> list:
        if not os.path.exists(history_file):
            print(f"  [ERROR] History file not found: {history_file}")
            return []

        items = []

        try:
            with open(history_file, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    lower = line.lower()

                    if any(domain in lower for domain in SUSPICIOUS_DOMAINS):
                        items.append(self.make_evidence_item(
                            artifact_id=stable_artifact_id("url", line.strip()),
                            evidence_type="suspicious_url",
                            value=line.strip(),
                            severity="high",
                            confidence=0.78
                        ))

        except Exception as e:
            print(f"  [ERROR] Browser parsing failed: {e}")

        print(f"  [BROWSER] → {len(items)} items")
        return items
