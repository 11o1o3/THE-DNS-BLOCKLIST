
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from concurrent.futures import ThreadPoolExecutor
from urllib.request import Request, urlopen
from urllib.parse import urlparse
import sqlite3
import ipaddress
import tempfile
import threading
import os
import re


class BlocklistMerger:
    def __init__(self, root):
        self.root = root
        self.root.title("Blocklist Merger")
        self.root.geometry("750x480")
        self.root.minsize(600, 400)

        self.db_path = None
        self.running = False
        self.domain_count = 0
        self.executor = ThreadPoolExecutor(max_workers=1)

        self.setup_ui()

    def setup_ui(self):
        main = ttk.Frame(self.root, padding=15)
        main.pack(fill="both", expand=True)

        ttk.Label(
            main,
            text="Blocklist URLs",
            font=("Arial", 11, "bold")
        ).pack(anchor="w")

        self.url_input = tk.Text(main, height=12, wrap="none")
        self.url_input.pack(fill="both", expand=True, pady=(5, 15))

        self.url_input.insert(
            "1.0",
            "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
        )

        controls = ttk.Frame(main)
        controls.pack(fill="x", pady=5)

        self.download_button = ttk.Button(
            controls,
            text="Download & Merge",
            command=self.start_download
        )
        self.download_button.pack(side="left")

        self.export_button = ttk.Button(
            controls,
            text="Export TXT",
            command=self.export,
            state="disabled"
        )
        self.export_button.pack(side="left", padx=8)

        self.clear_button = ttk.Button(
            controls,
            text="Clear",
            command=self.clear
        )
        self.clear_button.pack(side="left")

        ttk.Separator(main).pack(fill="x", pady=15)

        ttk.Label(
            main,
            text="Progress",
            font=("Arial", 10, "bold")
        ).pack(anchor="w")

        self.progress = ttk.Progressbar(
            main,
            mode="determinate",
            maximum=1000
        )
        self.progress.pack(fill="x", pady=8)

        self.status = tk.StringVar(value="Ready")
        ttk.Label(
            main,
            textvariable=self.status,
            wraplength=700
        ).pack(anchor="w", pady=5)

        self.statistics = tk.StringVar(
            value="Domains: 0 | Duplicates: 0"
        )

        ttk.Label(
            main,
            textvariable=self.statistics
        ).pack(anchor="w", pady=5)

    @staticmethod
    def valid_domain(domain):
        domain = domain.lower().rstrip(".")

        if not domain or len(domain) > 253:
            return False

        try:
            domain = domain.encode("idna").decode("ascii")
        except UnicodeError:
            return False

        if len(domain) > 253:
            return False

        labels = domain.split(".")

        if len(labels) < 2:
            return False

        return all(
            1 <= len(label) <= 63
            and re.fullmatch(
                r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?",
                label
            )
            for label in labels
        )

    @classmethod
    def extract_domains(cls, line):
        line = line.strip()

        if not line or line.startswith(("#", "!", "//")):
            return []

        if line.startswith("||"):
            candidate = re.split(r"[\^/]", line[2:], maxsplit=1)[0]
            candidates = [candidate]
        else:
            line = line.split("#", 1)[0].strip()
            parts = line.split()

            if not parts:
                return []

            try:
                ipaddress.ip_address(parts[0])
                candidates = parts[1:]
            except ValueError:
                candidates = parts

        domains = []

        for candidate in candidates:
            candidate = candidate.strip().lower()

            if "://" in candidate:
                candidate = urlparse(candidate).hostname or ""

            candidate = candidate.split("/", 1)[0]
            candidate = candidate.split(":", 1)[0]
            candidate = candidate.lstrip(".")

            if candidate.startswith("*."):
                candidate = candidate[2:]

            if cls.valid_domain(candidate):
                domains.append(
                    candidate.encode("idna").decode("ascii").rstrip(".")
                )

        return domains

    def update_progress(self, value, status):
        self.progress["value"] = value
        self.status.set(status)

    def start_download(self):
        urls = [
            line.strip()
            for line in self.url_input.get(
                "1.0", "end"
            ).splitlines()
            if line.strip()
        ]

        if not urls:
            messagebox.showwarning(
                "Missing URLs",
                "Please enter at least one URL."
            )
            return

        if any(
            urlparse(url).scheme not in ("http", "https")
            or not urlparse(url).hostname
            for url in urls
        ):
            messagebox.showerror(
                "Invalid URL",
                "Only HTTP and HTTPS URLs are supported."
            )
            return

        self.running = True
        self.download_button.config(state="disabled")
        self.export_button.config(state="disabled")
        self.clear_button.config(state="disabled")

        self.progress["value"] = 0
        self.statistics.set("Processing...")
        self.status.set("Initializing database...")

        self.executor.submit(self.process_urls, urls)

    def process_urls(self, urls):
        fd, db_path = tempfile.mkstemp(suffix=".sqlite")
        os.close(fd)

        total_entries = 0
        unique_entries = 0
        errors = []

        try:
            connection = sqlite3.connect(db_path)

            connection.execute("PRAGMA journal_mode = OFF")
            connection.execute("PRAGMA synchronous = OFF")
            connection.execute("PRAGMA cache_size = -64000")
            connection.execute("PRAGMA temp_store = FILE")

            connection.execute(
                "CREATE TABLE domains "
                "(domain TEXT PRIMARY KEY) WITHOUT ROWID"
            )

            batch = []

            for index, url in enumerate(urls):
                self.root.after(
                    0,
                    self.update_progress,
                    int(index / len(urls) * 1000),
                    f"Downloading {index + 1}/{len(urls)}: {url}"
                )

                try:
                    request = Request(
                        url,
                        headers={
                            "User-Agent": "BlocklistMerger/2.0"
                        }
                    )

                    with urlopen(request, timeout=60) as response:
                        length = int(
                            response.headers.get("Content-Length", 0)
                        )

                        downloaded = 0
                        lines = 0

                        while True:
                            raw_line = response.readline()

                            if not raw_line:
                                break

                            downloaded += len(raw_line)
                            lines += 1

                            line = raw_line.decode(
                                "utf-8",
                                errors="replace"
                            )

                            domains = self.extract_domains(line)

                            for domain in domains:
                                batch.append((domain,))
                                total_entries += 1

                            if len(batch) >= 5000:
                                cursor = connection.executemany(
                                    "INSERT OR IGNORE INTO domains "
                                    "VALUES (?)",
                                    batch
                                )
                                unique_entries += cursor.rowcount
                                batch.clear()

                            if lines % 2000 == 0:
                                fraction = (
                                    downloaded / length
                                    if length > 0 else 0
                                )

                                progress = (
                                    index + min(fraction, 1)
                                ) / len(urls) * 1000

                                self.root.after(
                                    0,
                                    self.update_progress,
                                    progress,
                                    f"Processing {index + 1}/{len(urls)} "
                                    f"| Lines: {lines:,} "
                                    f"| Unique domains: {unique_entries:,}"
                                )

                    if batch:
                        cursor = connection.executemany(
                            "INSERT OR IGNORE INTO domains VALUES (?)",
                            batch
                        )
                        unique_entries += cursor.rowcount
                        batch.clear()

                    connection.commit()

                except Exception as error:
                    errors.append(f"{url}: {error}")

            connection.close()

            self.root.after(
                0,
                self.finish_download,
                db_path,
                total_entries,
                unique_entries,
                errors
            )

        except Exception as error:
            try:
                connection.close()
            except Exception:
                pass

            self.root.after(
                0,
                self.processing_error,
                db_path,
                str(error)
            )

    def finish_download(
        self,
        db_path,
        total_entries,
        unique_entries,
        errors
    ):
        self.db_path = db_path
        self.domain_count = unique_entries
        self.running = False

        self.progress["value"] = 1000

        self.statistics.set(
            f"Domains: {unique_entries:,} | "
            f"Duplicates: {total_entries - unique_entries:,}"
        )

        self.status.set(
            f"Completed. {unique_entries:,} unique domains extracted."
        )

        self.download_button.config(state="normal")
        self.clear_button.config(state="normal")

        self.export_button.config(
            state="normal" if unique_entries else "disabled"
        )

        if errors:
            messagebox.showwarning(
                "Download completed with errors",
                "\n".join(errors[:10])
            )

    def processing_error(self, db_path, error):
        self.running = False
        self.download_button.config(state="normal")
        self.clear_button.config(state="normal")
        self.progress["value"] = 0
        self.status.set("Processing failed.")

        try:
            os.remove(db_path)
        except OSError:
            pass

        messagebox.showerror("Processing Error", error)

    def export(self):
        if not self.db_path or not self.domain_count:
            return

        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt")],
            initialfile="merged_blocklist.txt"
        )

        if not path:
            return

        self.export_button.config(state="disabled")
        self.download_button.config(state="disabled")
        self.clear_button.config(state="disabled")

        self.status.set("Exporting domains...")

        self.executor.submit(self.export_worker, path)

    def export_worker(self, path):
        try:
            connection = sqlite3.connect(self.db_path)

            cursor = connection.execute(
                "SELECT domain FROM domains ORDER BY domain"
            )

            exported = 0

            with open(
                path,
                "w",
                encoding="utf-8",
                newline="\n",
                buffering=1024 * 1024
            ) as file:

                while True:
                    rows = cursor.fetchmany(10000)

                    if not rows:
                        break

                    file.writelines(
                        domain[0] + "\n" for domain in rows
                    )

                    exported += len(rows)

                    if exported % 100000 == 0:
                        self.root.after(
                            0,
                            self.update_progress,
                            exported / self.domain_count * 1000,
                            f"Exporting: {exported:,} / "
                            f"{self.domain_count:,} domains"
                        )

            connection.close()

            self.root.after(
                0,
                self.finish_export,
                exported,
                None
            )

        except Exception as error:
            self.root.after(
                0,
                self.finish_export,
                0,
                str(error)
            )

    def finish_export(self, exported, error):
        self.download_button.config(state="normal")
        self.clear_button.config(state="normal")
        self.export_button.config(
            state="normal" if self.domain_count else "disabled"
        )

        if error:
            self.status.set("Export failed.")
            messagebox.showerror("Export Error", error)
            return

        self.progress["value"] = 1000
        self.status.set(f"Export completed: {exported:,} domains.")

        messagebox.showinfo(
            "Export Successful",
            f"Successfully exported {exported:,} domains."
        )

    def clear(self):
        if self.running:
            return

        self.url_input.delete("1.0", "end")
        self.progress["value"] = 0

        self.statistics.set("Domains: 0 | Duplicates: 0")
        self.status.set("Ready")

        self.export_button.config(state="disabled")

        self.domain_count = 0

        if self.db_path:
            try:
                os.remove(self.db_path)
            except OSError:
                pass

            self.db_path = None

    def close(self):
        if self.running:
            if not messagebox.askyesno(
                "Exit",
                "Processing is still running. Exit anyway?"
            ):
                return

        self.executor.shutdown(wait=False, cancel_futures=True)
        self.root.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    app = BlocklistMerger(root)
    root.protocol("WM_DELETE_WINDOW", app.close)
    root.mainloop()
