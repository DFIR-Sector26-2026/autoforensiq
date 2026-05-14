"""
AutoForensiq GUI launcher.

Run with:
    python -m src.gui
    python -m src.gui.launcher
"""

from __future__ import annotations

from pathlib import Path

import customtkinter as ctk

from src.gui.theme import (
    ACCENT, ACCENT_DIM, ACCENT_HOVER,
    BORDER, CARD_BG, DARK_BG,
    FONT_FAMILY, INPUT_BG,
    TEXT_MUTED, TEXT_PRIMARY, TEXT_SECONDARY,
)

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

ROOT_DIR = Path(__file__).resolve().parents[2]

_PROVIDER_MODELS: dict[str, list[str]] = {
    "anthropic": ["claude-sonnet-4-6", "claude-haiku-4-5-20251001", "claude-opus-4-7"],
    "openai":    ["gpt-4o", "gpt-4o-mini", "gpt-4-turbo"],
}


class AutoForensiqGUI(ctk.CTk):

    def __init__(self) -> None:
        super().__init__()
        self.title("AutoForensiq")
        self.geometry("960x860")
        self.minsize(820, 640)
        self.configure(fg_color=DARK_BG)

        # State (populated by later sections)
        self._report_path = ctk.StringVar()
        self._artifact_rows: list = []
        self._provider = ctk.StringVar(value="anthropic")
        self._model = ctk.StringVar(value="claude-sonnet-4-6")
        self._mock_mode = ctk.BooleanVar(value=True)
        self._skip_tools = ctk.BooleanVar(value=False)
        self._pipeline_running = False

        self._build_ui()

    # ── Layout skeleton ───────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        self._scroll = ctk.CTkScrollableFrame(
            self,
            fg_color=DARK_BG,
            scrollbar_button_color=BORDER,
            scrollbar_button_hover_color=ACCENT_DIM,
        )
        self._scroll.pack(fill="both", expand=True)
        self._scroll.grid_columnconfigure(0, weight=1)

        self._build_header()
        self._build_report_section()

    # ── Shared card helper ────────────────────────────────────────────────────

    def _card(self, title: str):
        """
        Create a labelled section card.
        Returns (card, body_frame, header_frame).
        """
        card = ctk.CTkFrame(
            self._scroll,
            fg_color=CARD_BG,
            corner_radius=12,
            border_width=1,
            border_color=BORDER,
        )
        card.pack(fill="x", padx=24, pady=(0, 16))
        card.grid_columnconfigure(0, weight=1)

        hdr = ctk.CTkFrame(card, fg_color="transparent")
        hdr.pack(fill="x", padx=20, pady=(16, 6))

        ctk.CTkLabel(
            hdr,
            text=title,
            font=(FONT_FAMILY, 10, "bold"),
            text_color=TEXT_MUTED,
        ).pack(side="left")

        body = ctk.CTkFrame(card, fg_color="transparent")
        body.pack(fill="x", padx=20, pady=(0, 16))
        body.grid_columnconfigure(0, weight=1)

        return card, body, hdr

    # ── Incident report section ───────────────────────────────────────────────

    def _build_report_section(self) -> None:
        _, body, _ = self._card("INCIDENT REPORT")

        row = ctk.CTkFrame(body, fg_color="transparent")
        row.pack(fill="x")
        row.grid_columnconfigure(0, weight=1)

        self._report_entry = ctk.CTkEntry(
            row,
            textvariable=self._report_path,
            placeholder_text="Select a plain-text incident report (.txt) …",
            font=(FONT_FAMILY, 12),
            fg_color=INPUT_BG,
            border_color=BORDER,
            text_color=TEXT_PRIMARY,
            placeholder_text_color=TEXT_MUTED,
            height=38,
        )
        self._report_entry.grid(row=0, column=0, sticky="ew", padx=(0, 10))

        ctk.CTkButton(
            row,
            text="Browse",
            command=self._browse_report,
            width=96, height=38, corner_radius=8,
            fg_color=ACCENT_DIM, hover_color=ACCENT,
            font=(FONT_FAMILY, 12, "bold"),
        ).grid(row=0, column=1)

        # Sample incident shortcut row
        samples_row = ctk.CTkFrame(body, fg_color="transparent")
        samples_row.pack(fill="x", pady=(10, 0))

        ctk.CTkLabel(
            samples_row,
            text="Samples:",
            font=(FONT_FAMILY, 11),
            text_color=TEXT_MUTED,
        ).pack(side="left", padx=(0, 8))

        samples = [
            ("Ransomware",    "01_ransomware.txt"),
            ("APT Intrusion", "02_apt_intrusion.txt"),
            ("Exfiltration",  "03_data_exfiltration.txt"),
            ("Insider Threat","04_insider_threat.txt"),
            ("Malware",       "05_malware_infection.txt"),
        ]
        for label, filename in samples:
            ctk.CTkButton(
                samples_row,
                text=label,
                command=lambda f=filename: self._load_sample(f),
                height=24, corner_radius=6,
                fg_color="#1e2433", hover_color=ACCENT_DIM,
                border_width=1, border_color=BORDER,
                font=(FONT_FAMILY, 10),
                text_color=TEXT_SECONDARY,
            ).pack(side="left", padx=(0, 6))

    def _browse_report(self) -> None:
        path = __import__("tkinter.filedialog", fromlist=["askopenfilename"]).askopenfilename(
            title="Select incident report",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            initialdir=str(ROOT_DIR / "tests" / "incidents"),
        )
        if path:
            self._report_path.set(path)

    def _load_sample(self, filename: str) -> None:
        self._report_path.set(str(ROOT_DIR / "tests" / "incidents" / filename))

    # ── Header ────────────────────────────────────────────────────────────────

    def _build_header(self) -> None:
        hdr = ctk.CTkFrame(self._scroll, fg_color="#111827", corner_radius=0)
        hdr.pack(fill="x", padx=0, pady=(0, 24))

        inner = ctk.CTkFrame(hdr, fg_color="transparent")
        inner.pack(padx=28, pady=(22, 18))

        ctk.CTkLabel(
            inner,
            text="⚡  AutoForensiq",
            font=(FONT_FAMILY, 26, "bold"),
            text_color=TEXT_PRIMARY,
        ).pack(anchor="w")

        ctk.CTkLabel(
            inner,
            text="Autonomous Digital Forensics  ·  Explainable AI  ·  SecTor 2026",
            font=(FONT_FAMILY, 12),
            text_color=TEXT_SECONDARY,
        ).pack(anchor="w", pady=(3, 0))


def main() -> None:
    app = AutoForensiqGUI()
    app.mainloop()


if __name__ == "__main__":
    main()
