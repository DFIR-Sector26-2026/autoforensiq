"""
AutoForensiq GUI launcher.

Run with:
    python -m src.gui
    python -m src.gui.launcher
"""

from __future__ import annotations

from pathlib import Path
from tkinter import filedialog

import customtkinter as ctk

from src.gui.theme import (
    ACCENT, ACCENT_DIM, ACCENT_HOVER,
    BORDER, CARD_BG, DARK_BG,
    FONT_FAMILY, INPUT_BG,
    TEXT_MUTED, TEXT_PRIMARY, TEXT_SECONDARY,
)
from src.gui.widgets import ArtifactRow

# Extension → artifact type (mirrors _map_evidence_files in autoforensiq.py)
_EXT_MAP: dict[str, str] = {
    ".dmp": "memory_dump", ".mem": "memory_dump", ".raw": "memory_dump",
    ".pcap": "pcap", ".pcapng": "pcap",
    ".img": "disk_image", ".dd": "disk_image", ".e01": "disk_image",
    ".dat": "registry_hive", ".hiv": "registry_hive",
    ".eml": "email_archive", ".msg": "email_archive",
    ".log": "log_files", ".evtx": "log_files",
}


def _detect_type(path: str) -> str:
    p = Path(path)
    low = str(p).lower()
    t = _EXT_MAP.get(p.suffix.lower())
    if t:
        return t
    if "memory" in low:
        return "memory_dump"
    if any(k in low for k in ("ntuser", "system", "software")):
        return "registry_hive"
    if "history" in low:
        return "browser_history"
    return "unknown"

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
        self._build_evidence_section()
        self._build_config_section()
        self._build_run_button()

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

    # ── Evidence file section ─────────────────────────────────────────────────

    def _build_evidence_section(self) -> None:
        _, body, hdr = self._card("EVIDENCE FILES")

        ctk.CTkButton(
            hdr, text="+ Add Evidence",
            command=self._add_evidence_files,
            width=120, height=28, corner_radius=6,
            fg_color=ACCENT_DIM, hover_color=ACCENT,
            font=(FONT_FAMILY, 11, "bold"),
        ).pack(side="right")

        self._evidence_list = ctk.CTkFrame(body, fg_color="transparent")
        self._evidence_list.pack(fill="x")

        self._empty_label = ctk.CTkLabel(
            self._evidence_list,
            text="No evidence files added yet.\nClick  + Add Evidence  to attach forensic artifacts.",
            font=(FONT_FAMILY, 12),
            text_color=TEXT_MUTED,
            justify="center",
        )
        self._empty_label.pack(pady=24)

        self._priority_hint = ctk.CTkLabel(
            body,
            text="ℹ  Use ↑ ↓ to reorder — priority is optional and does not affect which tools run",
            font=(FONT_FAMILY, 10),
            text_color=TEXT_MUTED,
        )
        self._priority_hint.pack(anchor="w", pady=(8, 0))
        self._priority_hint.pack_forget()

    def _add_evidence_files(self) -> None:
        paths = filedialog.askopenfilenames(
            title="Select evidence files",
            filetypes=[
                ("Forensic artifacts",
                 "*.dmp *.mem *.raw *.pcap *.pcapng *.img *.dd *.e01 "
                 "*.dat *.hiv *.log *.evtx *.eml *.msg"),
                ("Memory dumps",   "*.dmp *.mem *.raw"),
                ("PCAP",           "*.pcap *.pcapng"),
                ("Disk images",    "*.img *.dd *.e01"),
                ("Registry hives", "*.dat *.hiv"),
                ("Log files",      "*.log *.evtx"),
                ("Email",          "*.eml *.msg"),
                ("All files",      "*.*"),
            ],
            initialdir=str(ROOT_DIR / "data" / "test_cases"),
        )
        for p in paths:
            self._add_artifact_row(p)

    def _add_artifact_row(self, filepath: str) -> None:
        self._empty_label.pack_forget()

        row = ArtifactRow(
            self._evidence_list,
            filepath=filepath,
            artifact_type=_detect_type(filepath),
            index=len(self._artifact_rows),
            on_remove=lambda p=filepath: self._remove_artifact(p),
            on_move_up=lambda p=filepath: self._move_artifact(p, -1),
            on_move_down=lambda p=filepath: self._move_artifact(p, +1),
        )
        row.pack(fill="x", pady=(0, 6))
        self._artifact_rows.append(row)
        self._refresh_priorities()
        self._priority_hint.pack(anchor="w", pady=(8, 0))

    def _remove_artifact(self, filepath: str) -> None:
        for widget in self._evidence_list.winfo_children():
            if isinstance(widget, ArtifactRow) and widget.filepath == filepath:
                widget.destroy()
                break
        self._artifact_rows = [r for r in self._artifact_rows if r.filepath != filepath]
        self._refresh_priorities()
        if not self._artifact_rows:
            self._empty_label.pack(pady=24)
            self._priority_hint.pack_forget()

    def _move_artifact(self, filepath: str, direction: int) -> None:
        idx = next((i for i, r in enumerate(self._artifact_rows) if r.filepath == filepath), None)
        if idx is None:
            return
        new_idx = idx + direction
        if not (0 <= new_idx < len(self._artifact_rows)):
            return
        rows = self._artifact_rows
        rows[idx], rows[new_idx] = rows[new_idx], rows[idx]
        for r in rows:
            r.pack_forget()
        for r in rows:
            r.pack(fill="x", pady=(0, 6))
        self._refresh_priorities()

    def _refresh_priorities(self) -> None:
        for i, row in enumerate(self._artifact_rows):
            row.set_priority(i + 1)

    def get_artifact_order(self) -> list[str]:
        return [r.filepath for r in self._artifact_rows]

    def _browse_report(self) -> None:
        path = filedialog.askopenfilename(
            title="Select incident report",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            initialdir=str(ROOT_DIR / "tests" / "incidents"),
        )
        if path:
            self._report_path.set(path)

    def _load_sample(self, filename: str) -> None:
        self._report_path.set(str(ROOT_DIR / "tests" / "incidents" / filename))

    # ── Header ────────────────────────────────────────────────────────────────

    # ── Configuration section ─────────────────────────────────────────────────

    def _build_config_section(self) -> None:
        _, body, _ = self._card("CONFIGURATION")

        # Row 1 — provider + model dropdowns
        row1 = ctk.CTkFrame(body, fg_color="transparent")
        row1.pack(fill="x", pady=(0, 14))

        ctk.CTkLabel(
            row1, text="Provider",
            font=(FONT_FAMILY, 12), text_color=TEXT_SECONDARY, width=68,
        ).pack(side="left")

        self._provider_menu = ctk.CTkOptionMenu(
            row1,
            variable=self._provider,
            values=list(_PROVIDER_MODELS.keys()),
            command=self._on_provider_change,
            width=140, height=34, corner_radius=8,
            fg_color=INPUT_BG, button_color=ACCENT_DIM,
            button_hover_color=ACCENT, text_color=TEXT_PRIMARY,
            font=(FONT_FAMILY, 12),
        )
        self._provider_menu.pack(side="left", padx=(6, 24))

        ctk.CTkLabel(
            row1, text="Model",
            font=(FONT_FAMILY, 12), text_color=TEXT_SECONDARY, width=50,
        ).pack(side="left")

        self._model_menu = ctk.CTkOptionMenu(
            row1,
            variable=self._model,
            values=_PROVIDER_MODELS["anthropic"],
            width=240, height=34, corner_radius=8,
            fg_color=INPUT_BG, button_color=ACCENT_DIM,
            button_hover_color=ACCENT, text_color=TEXT_PRIMARY,
            font=(FONT_FAMILY, 12),
        )
        self._model_menu.pack(side="left", padx=6)

        # Row 2 — checkboxes
        row2 = ctk.CTkFrame(body, fg_color="transparent")
        row2.pack(fill="x")

        _chk = dict(
            font=(FONT_FAMILY, 12), text_color=TEXT_PRIMARY,
            checkmark_color="#ffffff", fg_color=ACCENT_DIM,
            hover_color=ACCENT, border_color=BORDER,
        )
        ctk.CTkCheckBox(
            row2, text="Mock mode  (no API key required)",
            variable=self._mock_mode, **_chk,
        ).pack(side="left", padx=(0, 32))

        ctk.CTkCheckBox(
            row2, text="Skip tools  (classifier only)",
            variable=self._skip_tools, **_chk,
        ).pack(side="left")

    def _on_provider_change(self, provider: str) -> None:
        models = _PROVIDER_MODELS.get(provider, [])
        self._model_menu.configure(values=models)
        self._model.set(models[0] if models else "")

    # ── Run button ────────────────────────────────────────────────────────────

    def _build_run_button(self) -> None:
        frame = ctk.CTkFrame(self._scroll, fg_color="transparent")
        frame.pack(fill="x", padx=24, pady=(0, 20))

        self._run_btn = ctk.CTkButton(
            frame,
            text="▶   Run Pipeline",
            command=self._run_pipeline,
            height=52, corner_radius=10,
            fg_color=ACCENT, hover_color=ACCENT_HOVER,
            font=(FONT_FAMILY, 15, "bold"),
            text_color="#ffffff",
        )
        self._run_btn.pack(fill="x")

    def _run_pipeline(self) -> None:
        pass  # wired up in the next commit

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
