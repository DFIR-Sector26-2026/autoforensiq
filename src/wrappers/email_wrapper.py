import os
from src.wrappers.base_wrapper import BaseWrapper, stable_artifact_id

SUSPICIOUS_KEYWORDS = [
    "urgent", "verify", "password", "bank",
    "login", "click here", "reset", "security alert"
]

class EmailWrapper(BaseWrapper):
    consumes = "email"

    def __init__(self):
        super().__init__("email")

    def run(self, email_file: str) -> list:
        if not os.path.exists(email_file):
            print(f"  [ERROR] Email file not found: {email_file}")
            return []

        items = []

        try:
            with open(email_file, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read().lower()

            for keyword in SUSPICIOUS_KEYWORDS:
                if keyword in content:
                    items.append(self.make_evidence_item(
                        artifact_id=stable_artifact_id("email", email_file, keyword),
                        evidence_type="phishing_email",
                        value=f"Keyword '{keyword}' found",
                        severity="high",
                        confidence=0.75
                    ))

        except Exception as e:
            print(f"  [ERROR] Email parsing failed: {e}")

        print(f"  [EMAIL] → {len(items)} items")
        return items
