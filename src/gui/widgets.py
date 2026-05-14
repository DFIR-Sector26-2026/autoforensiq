"""
Reusable GUI widgets for AutoForensiq launcher.
"""

from __future__ import annotations

from pathlib import Path

import customtkinter as ctk

from src.gui.theme import (
    ACCENT, ACCENT_DIM, ARTIFACT_BADGES, BORDER,
    CARD_BG, DANGER, FONT_FAMILY, TEXT_MUTED, TEXT_PRIMARY,
)


class ArtifactRow(ctk.CTkFrame):
    """
    One row in the evidence file list.

    Layout: drag-handle | type badge | filename | priority label | ↑ ↓ | ✕
    """

    def __init__(
        self,
        parent,
        filepath: str,
        artifact_type: str,
        index: int,
        on_remove,
        on_move_up,
        on_move_down,
        **kwargs,
    ) -> None:
        super().__init__(
            parent,
            fg_color="#1a1f2b",
            corner_radius=8,
            border_width=1,
            border_color=BORDER,
            **kwargs,
        )
        self.filepath = filepath
        self.artifact_type = artifact_type
        self._on_remove = on_remove
        self._on_move_up = on_move_up
        self._on_move_down = on_move_down
        self._priority_var = ctk.StringVar(value=f"#{index + 1}")

        self._build()

    def _build(self) -> None:
        self.grid_columnconfigure(2, weight=1)

        badge_cfg = ARTIFACT_BADGES.get(self.artifact_type, ARTIFACT_BADGES["unknown"])

        # Drag handle (visual only)
        ctk.CTkLabel(
            self, text="⠿",
            font=(FONT_FAMILY, 14), text_color=TEXT_MUTED, width=24,
        ).grid(row=0, column=0, padx=(12, 4), pady=10)

        # Type badge
        badge_frame = ctk.CTkFrame(
            self, fg_color=badge_cfg["bg"], corner_radius=6, width=124, height=26,
        )
        badge_frame.grid(row=0, column=1, padx=(4, 12), pady=10)
        badge_frame.grid_propagate(False)
        ctk.CTkLabel(
            badge_frame, text=badge_cfg["label"],
            font=(FONT_FAMILY, 10, "bold"), text_color=badge_cfg["fg"],
        ).place(relx=0.5, rely=0.5, anchor="center")

        # Filename
        ctk.CTkLabel(
            self, text=Path(self.filepath).name,
            font=(FONT_FAMILY, 12), text_color=TEXT_PRIMARY, anchor="w",
        ).grid(row=0, column=2, padx=(0, 12), pady=10, sticky="ew")

        # Priority label (#1, #2 …)
        self._priority_lbl = ctk.CTkLabel(
            self, textvariable=self._priority_var,
            font=("Consolas", 11, "bold"), text_color=ACCENT, width=30,
        )
        self._priority_lbl.grid(row=0, column=3, padx=4, pady=10)

        # Move up / down
        _btn = dict(
            width=28, height=28, corner_radius=6,
            fg_color=CARD_BG, hover_color=ACCENT_DIM,
            border_width=0, font=(FONT_FAMILY, 13), text_color=TEXT_MUTED,
        )
        ctk.CTkButton(self, text="↑", command=self._on_move_up, **_btn).grid(
            row=0, column=4, padx=(4, 2), pady=10)
        ctk.CTkButton(self, text="↓", command=self._on_move_down, **_btn).grid(
            row=0, column=5, padx=(2, 4), pady=10)

        # Remove
        ctk.CTkButton(
            self, text="✕", command=self._on_remove,
            width=28, height=28, corner_radius=6,
            fg_color="#3a1c1c", hover_color=DANGER,
            text_color="#f85149", font=(FONT_FAMILY, 12),
        ).grid(row=0, column=6, padx=(4, 12), pady=10)

    def set_priority(self, n: int) -> None:
        self._priority_var.set(f"#{n}")
