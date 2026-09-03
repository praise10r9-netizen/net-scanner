#!/usr/bin/env python3
"""Small operator console for the netscan JSON command-line interface."""

from __future__ import annotations

import argparse
import json
import queue
import subprocess
import threading
import tkinter as tk
from pathlib import Path
from tkinter import messagebox, ttk


class NetScanApp(tk.Tk):
    def __init__(self, binary: Path) -> None:
        super().__init__()
        self.binary = binary
        self.results_queue: queue.Queue[tuple[str, object]] = queue.Queue()
        self.scan_in_progress = False
        self.title("netscan | operator console")
        self.geometry("880x560")
        self.minsize(720, 440)
        self.configure(bg="#f4f6f8")
        self._build_style()
        self._build_layout()

    def _build_style(self) -> None:
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("TFrame", background="#f4f6f8")
        style.configure("Header.TLabel", background="#18212b", foreground="#f5f7fa", font=("DejaVu Sans", 18, "bold"))
        style.configure("Subheader.TLabel", background="#18212b", foreground="#aebbc8", font=("DejaVu Sans", 10))
        style.configure("TLabel", background="#f4f6f8", foreground="#26323d", font=("DejaVu Sans", 10))
        style.configure("TButton", padding=(14, 7), font=("DejaVu Sans", 10, "bold"))
        style.configure("Treeview", rowheight=30, font=("DejaVu Sans", 10))
        style.configure("Treeview.Heading", font=("DejaVu Sans", 10, "bold"))

    def _build_layout(self) -> None:
        header = tk.Frame(self, bg="#18212b", padx=24, pady=18)
        header.pack(fill="x")
        ttk.Label(header, text="NETSCAN", style="Header.TLabel").pack(anchor="w")
        ttk.Label(header, text="Fast evidence for the next network decision", style="Subheader.TLabel").pack(anchor="w", pady=(3, 0))

        controls = ttk.Frame(self, padding=(24, 18, 24, 10))
        controls.pack(fill="x")
        self.target = tk.StringVar(value="127.0.0.1")
        self.ports = tk.StringVar(value="22,80,443")
        self.timeout = tk.StringVar(value="1000")
        self._field(controls, "Target", self.target, 0, 0)
        self._field(controls, "Ports", self.ports, 0, 1)
        self._field(controls, "Timeout (ms)", self.timeout, 0, 2)
        self.scan_button = ttk.Button(controls, text="Run scan", command=self.start_scan)
        self.scan_button.grid(row=1, column=3, padx=(16, 0), sticky="ew")
        controls.columnconfigure(0, weight=3)
        controls.columnconfigure(1, weight=3)
        controls.columnconfigure(2, weight=1)
        controls.columnconfigure(3, weight=0)
        self.bind("<Return>", lambda _event: self.start_scan())

        body = ttk.Frame(self, padding=(24, 8, 24, 24))
        body.pack(fill="both", expand=True)
        self.status = ttk.Label(body, text="Ready", anchor="w")
        self.status.pack(fill="x", pady=(0, 8))
        columns = ("port", "state", "detail")
        self.table = ttk.Treeview(body, columns=columns, show="headings", selectmode="browse")
        self.table.heading("port", text="Port")
        self.table.heading("state", text="State")
        self.table.heading("detail", text="Evidence")
        self.table.column("port", width=90, anchor="center", stretch=False)
        self.table.column("state", width=130, anchor="center", stretch=False)
        self.table.column("detail", width=500, anchor="w")
        self.table.tag_configure("open", foreground="#087443")
        self.table.tag_configure("closed", foreground="#65717c")
        self.table.tag_configure("filtered", foreground="#a45b00")
        self.table.tag_configure("error", foreground="#b42318")
        scrollbar = ttk.Scrollbar(body, orient="vertical", command=self.table.yview)
        self.table.configure(yscrollcommand=scrollbar.set)
        self.table.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

    @staticmethod
    def _field(parent: ttk.Frame, label: str, variable: tk.StringVar, row: int, column: int) -> ttk.Entry:
        container = ttk.Frame(parent)
        container.grid(row=row, column=column, sticky="ew", padx=(0, 12))
        ttk.Label(container, text=label).pack(anchor="w")
        entry = ttk.Entry(container, textvariable=variable)
        entry.pack(fill="x", pady=(4, 0))
        entry.configure(exportselection=False)
        return entry

    def start_scan(self) -> None:
        if self.scan_in_progress:
            return
        target = self.target.get().strip()
        ports = self.ports.get().strip()
        timeout = self.timeout.get().strip()
        if not target or not ports:
            messagebox.showerror("Input needed", "Enter a target and at least one port.")
            return
        try:
            timeout_value = int(timeout)
            if not 50 <= timeout_value <= 60000:
                raise ValueError
        except ValueError:
            messagebox.showerror("Invalid timeout", "Timeout must be an integer between 50 and 60000 ms.")
            return
        self.scan_in_progress = True
        self.scan_button.configure(state="disabled")
        self.status.configure(text=f"Scanning {target} ...")
        for item in self.table.get_children():
            self.table.delete(item)
        threading.Thread(target=self._run_process, args=(target, ports, timeout_value), daemon=True).start()
        self.after(100, self._poll_results)

    def _run_process(self, target: str, ports: str, timeout: int) -> None:
        try:
            completed = subprocess.run(
                [str(self.binary), target, ports, str(timeout), "--json"],
                capture_output=True,
                text=True,
                check=False,
            )
            if completed.returncode != 0:
                detail = completed.stderr.strip() or "netscan returned an error"
                self.results_queue.put(("error", detail))
                return
            self.results_queue.put(("results", json.loads(completed.stdout)))
        except (OSError, json.JSONDecodeError) as error:
            self.results_queue.put(("error", str(error)))

    def _poll_results(self) -> None:
        try:
            kind, payload = self.results_queue.get_nowait()
        except queue.Empty:
            self.after(100, self._poll_results)
            return
        self.scan_in_progress = False
        self.scan_button.configure(state="normal")
        if kind == "error":
            self.status.configure(text="Scan failed")
            messagebox.showerror("Scan failed", str(payload))
            return
        data = payload
        results = data["results"]
        for result in results:
            self.table.insert("", "end", values=(result["port"], result["state"], result["detail"]), tags=(result["state"],))
        counts = {state: sum(item["state"] == state for item in results) for state in ("open", "closed", "filtered", "error")}
        self.status.configure(text=f"{data['target']} | {len(results)} ports | {counts['open']} open, {counts['filtered']} filtered")


def main() -> None:
    parser = argparse.ArgumentParser(description="Tkinter interface for netscan")
    parser.add_argument("--binary", type=Path, default=Path(__file__).parents[1] / "netscan")
    args = parser.parse_args()
    if not args.binary.exists():
        parser.error(f"scanner binary not found: {args.binary}; run make first")
    NetScanApp(args.binary).mainloop()


if __name__ == "__main__":
    main()