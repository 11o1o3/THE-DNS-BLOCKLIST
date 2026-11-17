
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
from urllib.parse import urlparse
import sqlite3
import tempfile
import threading
import ipaddress
import dns.resolver
import dns.exception
import time
import os
import re


class DNSChecker:
    def __init__(self, root):
        self.root = root
        self.root.title("DNS Domain Checker")
        self.root.geometry("850x720")
        self.root.minsize(700, 600)

        self.executor = ThreadPoolExecutor(max_workers=1)
        self.lock = threading.Lock()
        self.cancel_event = threading.Event()
        self.resolver_local = threading.local()

        self.state = {
            "stage": "Ready",
            "status": "Ready",
            "progress": 0,
            "checked": 0,
            "total": 0,
            "found": 0,
            "missing": 0,
            "errors": 0,
            "invalid": 0,
            "duplicates": 0,
            "speed": 0,
            "workers": {},
            "finished": None
        }

        self.started_at = 0
        self.worker_count = 12
        self.db_path = None
        self.running = False
        self.setup_ui()
        self.root.after(500, self.refresh_ui)

    def setup_ui(self):
        main = ttk.Frame(self.root, padding=15)
        main.pack(fill="both", expand=True)

        ttk.Label(
            main,
            text="Input Domain List",
            font=("Arial", 11, "bold")
        ).pack(anchor="w")

        input_frame = ttk.Frame(main)
        input_frame.pack(fill="x", pady=5)

        self.input_path = tk.StringVar()

        ttk.Entry(
            input_frame,
            textvariable=self.input_path
        ).pack(side="left", fill="x", expand=True)

        ttk.Button(
            input_frame,
            text="Browse",
            command=self.select_input
        ).pack(side="left", padx=(5, 0))

        ttk.Label(
            main,
            text="Output File",
            font=("Arial", 11, "bold")
        ).pack(anchor="w", pady=(10, 0))

        output_frame = ttk.Frame(main)
        output_frame.pack(fill="x", pady=5)

        self.output_path = tk.StringVar()

        ttk.Entry(
            output_frame,
            textvariable=self.output_path
        ).pack(side="left", fill="x", expand=True)

        ttk.Button(
            output_frame,
            text="Browse",
            command=self.select_output
        ).pack(side="left", padx=(5, 0))

        settings = ttk.LabelFrame(
            main,
            text="DNS Settings",
            padding=10
        )
        settings.pack(fill="x", pady=12)

        settings.columnconfigure(1, weight=1)
        settings.columnconfigure(3, weight=1)

        ttk.Label(settings, text="DNS Server").grid(
            row=0, column=0, sticky="w", padx=5, pady=5
        )

        self.dns_server = tk.StringVar(value="8.8.8.8")

        ttk.Entry(
            settings,
            textvariable=self.dns_server,
            width=18
        ).grid(row=0, column=1, sticky="ew", padx=5)

        ttk.Label(settings, text="Threads").grid(
            row=0, column=2, sticky="w", padx=5
        )

        self.threads = tk.IntVar(value=12)

        ttk.Spinbox(
            settings,
            from_=6,
            to=16,
            textvariable=self.threads,
            width=8
        ).grid(row=0, column=3, sticky="w", padx=5)

        ttk.Label(settings, text="Timeout (seconds)").grid(
            row=1, column=0, sticky="w", padx=5, pady=5
        )

        self.timeout = tk.IntVar(value=15)

        ttk.Spinbox(
            settings,
            from_=1,
            to=120,
            textvariable=self.timeout,
            width=8
        ).grid(row=1, column=1, sticky="w", padx=5)

        ttk.Label(
            settings,
            text="Record types: A + AAAA"
        ).grid(row=1, column=2, columnspan=2, sticky="w", padx=5)

        controls = ttk.Frame(main)
        controls.pack(fill="x", pady=5)

        self.start_button = ttk.Button(
            controls,
            text="Start DNS Check",
            command=self.start
        )
        self.start_button.pack(side="left")

        self.cancel_button = ttk.Button(
            controls,
            text="Cancel",
            command=self.cancel,
            state="disabled"
        )
        self.cancel_button.pack(side="left", padx=8)

        ttk.Separator(main).pack(fill="x", pady=12)

        ttk.Label(
            main,
            text="Progress",
            font=("Arial", 11, "bold")
        ).pack(anchor="w")

        self.progress = ttk.Progressbar(
            main,
            maximum=1000,
            mode="determinate"
        )
        self.progress.pack(fill="x", pady=8)

        self.status = tk.StringVar(value="Ready")
        ttk.Label(
            main,
            textvariable=self.status,
            wraplength=800
        ).pack(anchor="w", pady=3)

        self.eta = tk.StringVar(value="ETA: -- | Speed: --")
        ttk.Label(
            main,
            textvariable=self.eta
        ).pack(anchor="w", pady=3)

        stats = ttk.LabelFrame(
            main,
            text="Statistics",
            padding=10
        )
        stats.pack(fill="x", pady=10)

        self.statistics = tk.StringVar(
            value="Checked: 0 | Found: 0 | Missing: 0"
        )

        ttk.Label(
            stats,
            textvariable=self.statistics
        ).pack(anchor="w")

        self.extra_statistics = tk.StringVar(
            value="Errors: 0 | Invalid: 0 | Duplicates: 0"
        )

        ttk.Label(
            stats,
            textvariable=self.extra_statistics
        ).pack(anchor="w", pady=3)

        ttk.Label(
            main,
            text="Thread Activity",
            font=("Arial", 11, "bold")
        ).pack(anchor="w", pady=(5, 5))

        table_frame = ttk.Frame(main)
        table_frame.pack(fill="both", expand=True)

        self.thread_table = ttk.Treeview(
            table_frame,
            columns=("thread", "domain"),
            show="headings",
            height=10
        )

        self.thread_table.heading("thread", text="Thread")
        self.thread_table.heading("domain", text="Currently Checking")

        self.thread_table.column("thread", width=100, stretch=False)
        self.thread_table.column("domain", width=600)

        scrollbar = ttk.Scrollbar(
            table_frame,
            orient="vertical",
            command=self.thread_table.yview
        )

        self.thread_table.configure(
            yscrollcommand=scrollbar.set
        )

        self.thread_table.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

    def select_input(self):
        path = filedialog.askopenfilename(
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )

        if path:
            self.input_path.set(path)

    def select_output(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            initialfile="dns_filtered.txt",
            filetypes=[("Text files", "*.txt")]
        )

        if path:
            self.output_path.set(path)

    @staticmethod
    def extract_domain(line):
        line = line.strip()

        if not line or line.startswith(("#", "!", "//")):
            return None

        line = line.split("#", 1)[0].strip()
        parts = line.split()

        if not parts:
            return None

        try:
            ipaddress.ip_address(parts[0])
            parts = parts[1:]
        except ValueError:
            parts = parts[:1]

        if not parts:
            return None

        domain = parts[0].lower().rstrip(".")

        if domain.startswith("*."):
            domain = domain[2:]

        if "://" in domain:
            domain = urlparse(domain).hostname or ""

        domain = domain.split("/", 1)[0]
        domain = domain.split(":", 1)[0]

        try:
            domain = domain.encode("idna").decode("ascii")
        except UnicodeError:
            return None

        if len(domain) > 253:
            return None

        labels = domain.split(".")

        if len(labels) < 2:
            return None

        if any(
            not re.fullmatch(
                r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?",
                label
            ) or len(label) > 63
            for label in labels
        ):
            return None

        try:
            ipaddress.ip_address(domain)
            return None
        except ValueError:
            pass

        return domain

    def check_domain(self, domain, server, timeout):
        thread_name = threading.current_thread().name

        with self.lock:
            self.state["workers"][thread_name] = domain

        try:
            resolver = getattr(self.resolver_local, "resolver", None)

            if resolver is None or resolver.nameservers != [server]:
                resolver = dns.resolver.Resolver(configure=False)
                resolver.nameservers = [server]
                resolver.timeout = min(timeout, 3)
                self.resolver_local.resolver = resolver

            deadline = time.monotonic() + timeout
            transient_error = False

            for record_type in ("A", "AAAA"):
                remaining = deadline - time.monotonic()

                if remaining <= 0:
                    transient_error = True
                    break

                try:
                    answer = resolver.resolve(
                        domain,
                        record_type,
                        lifetime=remaining,
                        search=False
                    )

                    if answer.rrset is not None and len(answer) > 0:
                        return "found"

                except dns.resolver.NXDOMAIN:
                    return "missing"

                except dns.resolver.NoAnswer:
                    continue

                except (
                    dns.resolver.NoNameservers,
                    dns.resolver.LifetimeTimeout,
                    dns.exception.Timeout
                ):
                    transient_error = True

                except dns.exception.DNSException:
                    transient_error = True

            return "error" if transient_error else "missing"

        finally:
            with self.lock:
                self.state["workers"][thread_name] = "Idle"

    def start(self):
        source = self.input_path.get().strip()
        destination = self.output_path.get().strip()
        server = self.dns_server.get().strip()

        if not os.path.isfile(source):
            messagebox.showerror(
                "Invalid Input",
                "Please select a valid input file."
            )
            return

        if not destination:
            messagebox.showerror(
                "Missing Output",
                "Please select an output file before starting."
            )
            return

        if os.path.realpath(source) == os.path.realpath(destination):
            messagebox.showerror(
                "Invalid Output",
                "Input and output files must be different."
            )
            return

        try:
            ipaddress.ip_address(server)
            threads = int(self.threads.get())
            timeout = int(self.timeout.get())

            if not 6 <= threads <= 16:
                raise ValueError("Threads must be between 6 and 16.")

            if not 1 <= timeout <= 120:
                raise ValueError("Timeout must be between 1 and 120.")

        except ValueError as error:
            messagebox.showerror("Invalid Settings", str(error))
            return

        self.worker_count = threads
        self.cancel_event.clear()
        self.running = True
        self.started_at = time.monotonic()

        with self.lock:
            self.state.update({
                "stage": "Importing",
                "status": "Importing domains...",
                "progress": 0,
                "checked": 0,
                "total": 0,
                "found": 0,
                "missing": 0,
                "errors": 0,
                "invalid": 0,
                "duplicates": 0,
                "speed": 0,
                "workers": {},
                "finished": None
            })

        for item in self.thread_table.get_children():
            self.thread_table.delete(item)

        for i in range(threads):
            name = f"DNS_{i}"
            self.thread_table.insert(
                "",
                "end",
                iid=name,
                values=(f"Thread {i + 1}", "Idle")
            )

        self.progress["value"] = 0
        self.start_button.config(state="disabled")
        self.cancel_button.config(state="normal")

        self.executor.submit(
            self.process,
            source,
            destination,
            server,
            threads,
            timeout
        )

    def process(self, source, destination, server, threads, timeout):
        db_path = None
        connection = None

        try:
            fd, db_path = tempfile.mkstemp(suffix=".sqlite")
            os.close(fd)
            self.db_path = db_path

            connection = sqlite3.connect(db_path)

            connection.execute("PRAGMA journal_mode = OFF")
            connection.execute("PRAGMA synchronous = OFF")
            connection.execute("PRAGMA cache_size = -64000")
            connection.execute("PRAGMA temp_store = FILE")

            connection.execute(
                "CREATE TABLE domains "
                "(domain TEXT PRIMARY KEY) WITHOUT ROWID"
            )

            connection.execute(
                "CREATE TABLE results "
                "(domain TEXT PRIMARY KEY) WITHOUT ROWID"
            )

            file_size = os.path.getsize(source)
            valid_count = 0
            invalid_count = 0
            unique_count = 0
            batch = []

            with open(source, "r", encoding="utf-8", errors="replace") as file:
                while True:
                    if self.cancel_event.is_set():
                        raise InterruptedError("Operation cancelled.")

                    line = file.readline()

                    if not line:
                        break

                    domain = self.extract_domain(line)

                    if domain:
                        valid_count += 1
                        batch.append((domain,))
                    else:
                        if line.strip() and not line.lstrip().startswith(("#", "!")):
                            invalid_count += 1

                    if len(batch) >= 5000:
                        cursor = connection.executemany(
                            "INSERT OR IGNORE INTO domains VALUES (?)",
                            batch
                        )
                        unique_count += cursor.rowcount
                        batch.clear()
                        connection.commit()

                    if file_size and file.tell() % (1024 * 1024) < 100:
                        progress = min(
                            50,
                            int(file.tell() / file_size * 50)
                        )

                        with self.lock:
                            self.state["progress"] = progress * 10
                            self.state["status"] = (
                                f"Importing domains... "
                                f"{unique_count:,} unique entries"
                            )

            if batch:
                cursor = connection.executemany(
                    "INSERT OR IGNORE INTO domains VALUES (?)",
                    batch
                )
                unique_count += cursor.rowcount
                batch.clear()

            connection.commit()

            duplicates = valid_count - unique_count

            with self.lock:
                self.state.update({
                    "stage": "Checking",
                    "total": unique_count,
                    "invalid": invalid_count,
                    "duplicates": duplicates,
                    "status": "Starting DNS checks..."
                })

            if unique_count == 0:
                raise ValueError("No valid domains found in input file.")

            started = time.monotonic()
            checked = 0
            found = 0
            missing = 0
            errors = 0
            result_batch = []

            cursor = connection.execute(
                "SELECT domain FROM domains"
            )

            with ThreadPoolExecutor(
                max_workers=threads,
                thread_name_prefix="DNS"
            ) as pool:

                pending = set()
                max_pending = threads * 4
                exhausted = False

                while pending or not exhausted:
                    if self.cancel_event.is_set():
                        raise InterruptedError("Operation cancelled.")

                    while not exhausted and len(pending) < max_pending:
                        row = cursor.fetchone()

                        if row is None:
                            exhausted = True
                            break

                        pending.add(
                            pool.submit(
                                self.check_domain,
                                row[0],
                                server,
                                timeout
                            )
                        )

                    if not pending:
                        break

                    completed, pending = wait(
                        pending,
                        return_when=FIRST_COMPLETED
                    )

                    for future in completed:
                        try:
                            result = future.result()
                        except Exception:
                            result = "error"

                        checked += 1

                        if result == "found":
                            found += 1
                            result_batch.append(
                                (future.result() if False else None,)
                            )
                        elif result == "missing":
                            missing += 1
                        else:
                            errors += 1

                    if result_batch:
                        result_batch.clear()

                    elapsed = max(time.monotonic() - started, 0.001)
                    speed = checked / elapsed

                    progress = 50 + int(
                        checked / unique_count * 850
                    )

                    with self.lock:
                        self.state.update({
                            "checked": checked,
                            "found": found,
                            "missing": missing,
                            "errors": errors,
                            "speed": speed,
                            "progress": progress,
                            "status": (
                                f"Checking DNS records... "
                                f"{checked:,} / {unique_count:,}"
                            )
                        })

                    if checked % 1000 < len(completed):
                        connection.commit()

            if self.cancel_event.is_set():
                raise InterruptedError("Operation cancelled.")

            with self.lock:
                self.state.update({
                    "stage": "Exporting",
                    "status": "Exporting sorted domains...",
                    "progress": 900
                })

            export_connection = connection

            with open(
                destination,
                "w",
                encoding="utf-8",
                newline="\n",
                buffering=1024 * 1024
            ) as output:

                export_cursor = export_connection.execute(
                    "SELECT domain FROM results ORDER BY domain"
                )

                exported = 0

                while True:
                    rows = export_cursor.fetchmany(10000)

                    if not rows:
                        break

                    output.writelines(
                        row[0] + "\n" for row in rows
                    )

                    exported += len(rows)

                    with self.lock:
                        self.state["progress"] = (
                            900 + int(exported / max(found, 1) * 100)
                        )

            connection.close()
            connection = None

            self.state["finished"] = {
                "success": True,
                "exported": exported,
                "checked": checked,
                "found": found,
                "missing": missing,
                "errors": errors,
                "invalid": invalid_count,
                "duplicates": duplicates
            }

        except InterruptedError:
            self.state["finished"] = {
                "success": False,
                "cancelled": True
            }

        except Exception as error:
            self.state["finished"] = {
                "success": False,
                "error": str(error)
            }

        finally:
            if connection:
                connection.close()

            if db_path:
                try:
                    os.remove(db_path)
                except OSError:
                    pass

            self.db_path = None

    def refresh_ui(self):
        with self.lock:
            state = self.state.copy()
            workers = self.state["workers"].copy()

        self.progress["value"] = state["progress"]

        self.status.set(state["status"])

        for name, domain in workers.items():
            if self.thread_table.exists(name):
                self.thread_table.item(
                    name,
                    values=(
                        f"Thread {int(name.split('_')[1]) + 1}",
                        domain
                    )
                )

        self.statistics.set(
            f"Checked: {state['checked']:,} | "
            f"Found: {state['found']:,} | "
            f"Missing: {state['missing']:,}"
        )

        self.extra_statistics.set(
            f"Errors: {state['errors']:,} | "
            f"Invalid: {state['invalid']:,} | "
            f"Duplicates: {state['duplicates']:,}"
        )

        checked = state["checked"]
        total = state["total"]
        speed = state["speed"]

        if state["stage"] == "Checking" and speed > 0:
            remaining = max(0, total - checked)
            seconds = remaining / speed

            self.eta.set(
                f"ETA: {self.format_time(seconds)} | "
                f"Speed: {speed:,.0f} domains/s"
            )
        else:
            self.eta.set("ETA: -- | Speed: --")

        finished = state["finished"]

        if finished and self.running:
            self.running = False
            self.start_button.config(state="normal")
            self.cancel_button.config(state="disabled")

            if finished.get("success"):
                self.progress["value"] = 1000

                self.status.set(
                    f"Completed. {finished['exported']:,} domains exported."
                )

                messagebox.showinfo(
                    "DNS Check Completed",
                    f"Successfully exported {finished['exported']:,} domains.\n\n"
                    f"Checked: {finished['checked']:,}\n"
                    f"Found: {finished['found']:,}\n"
                    f"Missing: {finished['missing']:,}\n"
                    f"Errors: {finished['errors']:,}\n"
                    f"Invalid: {finished['invalid']:,}\n"
                    f"Duplicates: {finished['duplicates']:,}"
                )

            elif finished.get("cancelled"):
                self.status.set("Operation cancelled.")
                self.progress["value"] = 0

            else:
                self.status.set("Processing failed.")
                messagebox.showerror(
                    "DNS Checker Error",
                    finished["error"]
                )

        if self.root.winfo_exists():
            self.root.after(500, self.refresh_ui)

    @staticmethod
    def format_time(seconds):
        seconds = int(seconds)

        hours, remainder = divmod(seconds, 3600)
        minutes, seconds = divmod(remainder, 60)

        if hours:
            return f"{hours}h {minutes}m"

        if minutes:
            return f"{minutes}m {seconds}s"

        return f"{seconds}s"

    def cancel(self):
        if not self.running:
            return

        if messagebox.askyesno(
            "Cancel",
            "Do you really want to cancel the DNS check?"
        ):
            self.cancel_event.set()
            self.cancel_button.config(state="disabled")
            self.status.set("Cancelling...")

    def close(self):
        if self.running:
            if not messagebox.askyesno(
                "Exit",
                "DNS checks are running. Exit anyway?"
            ):
                return

            self.cancel_event.set()

        self.executor.shutdown(
            wait=False,
            cancel_futures=True
        )

        self.root.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    app = DNSChecker(root)
    root.protocol("WM_DELETE_WINDOW", app.close)
    root.mainloop()
