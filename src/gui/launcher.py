"""
AutoForensiq GUI launcher.

Run with:
    python -m src.gui
    python -m src.gui.launcher
"""

from __future__ import annotations

import subprocess
import sys
import threading
import webbrowser
from pathlib import Path
from tkinter import filedialog, messagebox

import customtkinter as ctk

from src.gui.theme import (
    ACCENT, ACCENT_DIM, ACCENT_HOVER,
    BORDER, CARD_BG, DARK_BG,
    FONT_FAMILY, INPUT_BG,
    TEXT_MUTED, TEXT_PRIMARY, TEXT_SECONDARY,
)
from src.gui.widgets import ArtifactRow

# Extension: artifact type (mirrors _map_evidence_files in autoforensiq.py). The single source for the evidence-dialog filter groups below
_EXT_MAP: dict[str, str] = {
    ".dmp": "memory_dump", ".mem": "memory_dump", ".raw": "memory_dump", ".vmem": "memory_dump",
    ".pcap": "pcap", ".pcapng": "pcap",
    ".img": "disk_image", ".dd": "disk_image", ".e01": "disk_image", ".dmg": "disk_image",
    ".dat": "registry_hive", ".hiv": "registry_hive",
    ".eml": "email_archive", ".msg": "email_archive",
    ".log": "text_log", ".evtx": "log_files",
}

# Artifact type → evidence-dialog filter label, in display order.
_TYPE_LABELS = [
    ("memory_dump",   "Memory dumps"),
    ("pcap",          "PCAP"),
    ("disk_image",    "Disk images"),
    ("registry_hive", "Registry hives"),
    ("log_files",     "Event logs"),
    ("text_log",      "Text logs"),
    ("email_archive", "Email"),
]


def _detect_type(path: str) -> str:
    p = Path(path)
    low = str(p).lower()
    t = _EXT_MAP.get(p.suffix.lower())
    if t:
        return t
    # .csv is conditional, not in _EXT_MAP: the CLI routes it to the email analyzer only when the
    # name signals mail (D4), so only those badge as email — a bare data.csv stays unknown.
    if p.suffix.lower() == ".csv" and any(h in low for h in ("email", "mail", "inbox", "phish", "spam")):
        return "email_archive"
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
    "deepseek":  ["deepseek-chat", "deepseek-reasoner"],
}

# Tool name → display label
_TOOLS: list[tuple[str, str]] = [
    ("volatility3", "Volatility3"),
    ("memprocfs",   "MemProcFS"),
    ("tshark",      "Tshark"),
    ("tsk_fls",     "SleuthKit"),
    ("regripper",   "RegRipper"),
    ("plaso",       "Plaso"),
    ("email",       "Email"),
    ("browser",     "Browser"),
]


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
        self._known_bad = ctk.StringVar()
        self._tool_vars: dict[str, ctk.BooleanVar] = {
            name: ctk.BooleanVar(value=True) for name, _ in _TOOLS
        }
        self._pipeline_running = False
        self._dashboard_proc: subprocess.Popen | None = None

        self._build_ui()
        self.protocol("WM_DELETE_WINDOW", self._on_close)

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
        self._build_console()

    # ── Shared card helper ────────────────────────────────────────────────────

    def _card(self, title: str):
        """Create a labelled section card. Returns (card, body_frame, header_frame)."""
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
        # Multi-select dialog (Ctrl/Shift+click). Tk patterns are case-sensitive on Linux, so each
        # extension is offered in both cases (dev01-c-drive.E01 / MEMORY.DMP were invisible before).
        groups = {
            label: [ext.lstrip(".") for ext, t in _EXT_MAP.items() if t == atype]
            for atype, label in _TYPE_LABELS
        }
        # Conditional in _detect_type, so not in _EXT_MAP — but still selectable here.
        groups["Email"].append("csv")

        def both_cases(exts: list[str]) -> str:
            return " ".join(f"*.{e} *.{e.upper()}" for e in exts)

        paths = filedialog.askopenfilenames(
            title="Select evidence files",
            filetypes=[
                ("Forensic artifacts", both_cases([e for exts in groups.values() for e in exts])),
                *[(label, both_cases(exts)) for label, exts in groups.items()],
                ("All files", "*.*"),
            ],
            initialdir=str(ROOT_DIR.parent),
        )
        existing = set(self.get_artifact_order())
        for p in paths:
            if p not in existing:
                self._add_artifact_row(p)
                existing.add(p)

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

        # Row 3 — tool selection
        row3 = ctk.CTkFrame(body, fg_color="transparent")
        row3.pack(fill="x", pady=(14, 0))

        ctk.CTkLabel(
            row3, text="Tools",
            font=(FONT_FAMILY, 12), text_color=TEXT_SECONDARY, width=68,
        ).pack(side="left")

        tools_inner = ctk.CTkFrame(row3, fg_color="transparent")
        tools_inner.pack(side="left", fill="x", expand=True)

        _tool_chk = dict(
            font=(FONT_FAMILY, 11), text_color=TEXT_PRIMARY,
            checkmark_color="#ffffff", fg_color=ACCENT_DIM,
            hover_color=ACCENT, border_color=BORDER,
        )
        for name, label in _TOOLS:
            ctk.CTkCheckBox(
                tools_inner, text=label,
                variable=self._tool_vars[name],
                **_tool_chk,
            ).pack(side="left", padx=(0, 16))

        self._all_tools_btn = ctk.CTkButton(
            tools_inner, text="All",
            command=self._select_all_tools,
            width=40, height=22, corner_radius=6,
            fg_color="transparent", hover_color=BORDER,
            border_width=1, border_color=BORDER,
            font=(FONT_FAMILY, 10), text_color=TEXT_MUTED,
        )
        self._all_tools_btn.pack(side="left")

        # Row 4 — per-case known-bad hosts (BUGS 2.1: analyst threat intel → reputation match)
        row4 = ctk.CTkFrame(body, fg_color="transparent")
        row4.pack(fill="x", pady=(14, 0))

        ctk.CTkLabel(
            row4, text="Known-bad",
            font=(FONT_FAMILY, 12), text_color=TEXT_SECONDARY, width=68,
        ).pack(side="left")

        self._known_bad_entry = ctk.CTkEntry(
            row4,
            textvariable=self._known_bad,
            placeholder_text="Per-case bad domains / IPs, space- or comma-separated (optional)…",
            font=(FONT_FAMILY, 12),
            fg_color=INPUT_BG,
            border_color=BORDER,
            text_color=TEXT_PRIMARY,
            placeholder_text_color=TEXT_MUTED,
            height=34,
        )
        self._known_bad_entry.pack(side="left", fill="x", expand=True, padx=(6, 0))

    def _select_all_tools(self) -> None:
        for var in self._tool_vars.values():
            var.set(True)

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

    # ── Output console ────────────────────────────────────────────────────────

    def _build_console(self) -> None:
        _, body, hdr = self._card("PIPELINE OUTPUT")

        self._copy_btn = ctk.CTkButton(
            hdr, text="Copy",
            command=self._copy_console,
            width=56, height=24, corner_radius=6,
            fg_color="transparent", hover_color=BORDER,
            border_width=1, border_color=BORDER,
            font=(FONT_FAMILY, 10), text_color=TEXT_MUTED,
        )
        self._copy_btn.pack(side="right")

        self._console = ctk.CTkTextbox(
            body,
            height=240,
            fg_color="#010409",
            text_color="#3fb950",
            font=("Consolas", 11),
            corner_radius=8,
            border_width=1,
            border_color=BORDER,
            wrap="word",
            state="disabled",
        )
        self._console.pack(fill="x")
        self._console_write("Waiting for pipeline run…\n")

    def _console_write(self, text: str) -> None:
        self._console.configure(state="normal")
        self._console.insert("end", text)
        self._console.see("end")
        self._console.configure(state="disabled")

    def _clear_console(self) -> None:
        self._console.configure(state="normal")
        self._console.delete("1.0", "end")
        self._console.configure(state="disabled")

    def _copy_console(self) -> None:
        """Copy the entire console output to the clipboard."""
        text = self._console.get("1.0", "end-1c")
        if not text:
            return
        self.clipboard_clear()
        self.clipboard_append(text)
        self.update_idletasks()
        # brief visual confirmation on the Copy button
        self._copy_btn.configure(text="Copied!")
        self.after(1200, lambda: self._copy_btn.configure(text="Copy"))

    # ── Pipeline execution ────────────────────────────────────────────────────

    def _run_pipeline(self) -> None:
        if self._pipeline_running:
            return

        report = self._report_path.get().strip()
        if not report:
            messagebox.showwarning("Missing report", "Please select an incident report file.")
            return
        if not Path(report).exists():
            messagebox.showerror("File not found", f"Report not found:\n{report}")
            return

        self._pipeline_running = True
        self._run_btn.configure(text="⏳   Running…", state="disabled", fg_color=ACCENT_DIM)
        self._clear_console()

        threading.Thread(target=self._pipeline_thread, args=(report,), daemon=True).start()

    def _pipeline_thread(self, report: str) -> None:
        cmd = [sys.executable, str(ROOT_DIR / "autoforensiq.py"), "--report", report]

        if self._mock_mode.get():
            cmd.append("--mock")
        if self._skip_tools.get():
            cmd.append("--skip-tools")

        evidence = self.get_artifact_order()
        if evidence:
            cmd += ["--evidence"] + evidence

        selected_tools = [name for name, _ in _TOOLS if self._tool_vars[name].get()]
        if selected_tools and len(selected_tools) < len(_TOOLS):
            cmd += ["--tools"] + selected_tools

        known_bad = self._known_bad.get().replace(",", " ").split()
        if known_bad:
            cmd += ["--known-bad"] + known_bad

        if not self._mock_mode.get():
            provider = self._provider.get()
            model    = self._model.get()
            if provider:
                cmd += ["--provider", provider]
            if model:
                cmd += ["--model", model]

        self.after(0, self._console_write, f"$ {' '.join(cmd)}\n\n")

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                cwd=str(ROOT_DIR),
            )
            for line in proc.stdout:
                self.after(0, self._console_write, line)
            proc.wait()
            status = "✓  Pipeline complete." if proc.returncode == 0 else f"✗  Exit code {proc.returncode}"
            self.after(0, self._console_write, f"\n{status}\n")
            if proc.returncode == 0:
                self.after(0, self._launch_dashboard)
        except Exception as exc:
            self.after(0, self._console_write, f"\n[ERROR] {exc}\n")
        finally:
            self.after(0, self._restore_run_btn)

    def _launch_dashboard(self) -> None:
        """Open the web dashboard once a run finishes. The pipeline already
        published its data to dashboard/public/data/, so we just start the dev
        server (which opens the browser itself) — or reopen it if already up.

        We run the vite binary directly rather than via `npm run dev`: npm would
        spawn vite as a child that survives terminate(), orphaning the server."""
        url = "http://localhost:5173"
        dash_dir = ROOT_DIR / "dashboard"
        vite_bin = dash_dir / "node_modules" / ".bin" / "vite"

        if not vite_bin.exists():
            self._console_write(
                "\n[DASHBOARD] Skipped — run `npm install` in dashboard/ first.\n")
            return

        # Already running from an earlier run: just bring the browser back.
        if self._dashboard_proc and self._dashboard_proc.poll() is None:
            webbrowser.open(url)
            self._console_write(f"\n[DASHBOARD] Reopened {url}\n")
            return

        self._dashboard_proc = subprocess.Popen(
            [str(vite_bin), "--port", "5173", "--strictPort", "--open"],
            cwd=str(dash_dir),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self._console_write(f"\n[DASHBOARD] Server starting → {url}\n")

    def _on_close(self) -> None:
        """Stop the dashboard dev server (if we started one) before quitting."""
        if self._dashboard_proc and self._dashboard_proc.poll() is None:
            self._dashboard_proc.terminate()
        self.destroy()

    def _restore_run_btn(self) -> None:
        self._pipeline_running = False
        self._run_btn.configure(text="▶   Run Pipeline", state="normal", fg_color=ACCENT)

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
