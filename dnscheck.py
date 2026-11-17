
import sys
import os
import re
import ipaddress
import sqlite3
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
from urllib.parse import urlsplit

import dns.resolver
import dns.exception
import psutil

from PySide6.QtCore import QObject, Signal
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QGridLayout, QLabel, QLineEdit, QPushButton, QFileDialog,
    QSpinBox, QProgressBar, QTableWidget, QTableWidgetItem,
    QHeaderView, QMessageBox, QGroupBox
)


def normalize_domain(line):
    """Normalize a line into a valid domain name.

    :param line: Raw line from the input file.
    :return: Normalized domain or None.
    """
    value = line.strip()

    if not value or value.startswith(("#", "!")):
        return None

    parts = value.split()

    if len(parts) > 1:
        try:
            ipaddress.ip_address(parts[0])
            value = parts[1]
        except ValueError:
            value = parts[0]

    value = value.strip().strip("|").strip("^").strip()

    if "://" in value:
        value = urlsplit(value).hostname or ""

    value = value.split("/")[0].split("?")[0].split("#")[0]
    value = value.removeprefix("*.")
    value = value.rstrip(".")

    if not value or ":" in value:
        return None

    try:
        value = value.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None

    if len(value) > 253:
        return None

    labels = value.split(".")
    pattern = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")

    if len(labels) < 2 or any(not pattern.fullmatch(label) for label in labels):
        return None

    return value


class WorkerSignals(QObject):
    stage = Signal(str)
    progress = Signal(int, int, int, float, float, int, int)
    worker_update = Signal(str, str, str)
    finished = Signal(str)
    error = Signal(str)


class DNSChecker:
    def __init__(
        self,
        input_file,
        output_file,
        dns_servers,
        min_threads,
        max_threads,
        cpu_limit,
        ram_limit,
        timeout,
        qps,
        signals,
        stop_event
    ):
        self.input_file = input_file
        self.output_file = output_file
        self.dns_servers = dns_servers
        self.min_threads = min_threads
        self.max_threads = max_threads
        self.cpu_limit = cpu_limit
        self.ram_limit = ram_limit
        self.timeout = timeout
        self.qps = qps
        self.signals = signals
        self.stop_event = stop_event
        self.done = 0
        self.success = 0
        self.total = 0
        self.active_limit = min_threads

    def check_domain(self, domain):
        """Check whether a domain has an A or AAAA DNS record.

        :param domain: Domain to resolve.
        :return: Tuple containing domain and resolution status.
        """
        worker = threading.current_thread().name
        self.signals.worker_update.emit(worker, domain, "Checking")

        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = self.dns_servers
        resolver.timeout = self.timeout
        resolver.lifetime = self.timeout

        result = False

        for record_type in ("A", "AAAA"):
            try:
                resolver.resolve(
                    domain,
                    record_type,
                    lifetime=self.timeout,
                    search=False
                )
                result = True
                break
            except (dns.exception.DNSException, OSError):
                pass

        self.signals.worker_update.emit(worker, domain, "Idle")
        return domain, result

    def load_domains(self, connection):
        """Load and deduplicate domains using SQLite.

        :param connection: SQLite database connection.
        :return: Number of unique domains.
        """
        self.signals.stage.emit("Loading domains and removing duplicates...")

        connection.execute(
            "CREATE TABLE domains (domain TEXT PRIMARY KEY)"
        )
        connection.execute(
            "CREATE TABLE results (domain TEXT PRIMARY KEY)"
        )

        batch = []

        with open(self.input_file, "r", encoding="utf-8", errors="ignore") as file:
            for line in file:
                if self.stop_event.is_set():
                    break

                domain = normalize_domain(line)

                if domain:
                    batch.append((domain,))

                if len(batch) >= 5000:
                    connection.executemany(
                        "INSERT OR IGNORE INTO domains VALUES (?)",
                        batch
                    )
                    connection.commit()
                    batch.clear()

        if batch:
            connection.executemany(
                "INSERT OR IGNORE INTO domains VALUES (?)",
                batch
            )
            connection.commit()

        self.total = connection.execute(
            "SELECT COUNT(*) FROM domains"
        ).fetchone()[0]

        return self.total

    def export_results(self, connection):
        """Export successful domains in alphabetical order.

        :param connection: SQLite database connection.
        """
        self.signals.stage.emit("Exporting results...")

        with open(self.output_file, "w", encoding="utf-8") as file:
            cursor = connection.execute(
                "SELECT domain FROM results ORDER BY domain"
            )

            while True:
                rows = cursor.fetchmany(10000)

                if not rows:
                    break

                file.writelines(domain + "\n" for (domain,) in rows)

    def run(self):
        """Execute the DNS checking process."""
        database_path = None

        try:
            descriptor, database_path = tempfile.mkstemp(
                prefix="dns_checker_",
                suffix=".sqlite"
            )
            os.close(descriptor)

            connection = sqlite3.connect(database_path)
            self.load_domains(connection)

            if self.stop_event.is_set():
                self.export_results(connection)
                connection.close()
                self.signals.finished.emit("Cancelled")
                return

            if self.total == 0:
                self.export_results(connection)
                connection.close()
                self.signals.finished.emit("No valid domains found")
                return

            self.signals.stage.emit("DNS check running...")

            psutil.cpu_percent(interval=None)

            executor = ThreadPoolExecutor(
                max_workers=self.max_threads,
                thread_name_prefix="DNS"
            )

            futures = {}
            domain_cursor = connection.execute(
                "SELECT domain FROM domains"
            )

            next_submit = time.monotonic()
            next_sample = time.monotonic() + 2
            cpu_usage = 0.0
            ram_usage = psutil.virtual_memory().percent
            exhausted = False

            try:
                while True:
                    now = time.monotonic()

                    if now >= next_sample:
                        cpu_usage = psutil.cpu_percent(interval=None)
                        ram_usage = psutil.virtual_memory().percent

                        if (
                            cpu_usage > self.cpu_limit
                            or ram_usage > self.ram_limit
                        ):
                            self.active_limit = max(
                                self.min_threads,
                                int(self.active_limit * 0.75)
                            )
                        elif (
                            cpu_usage < self.cpu_limit - 5
                            and ram_usage < self.ram_limit - 5
                        ):
                            self.active_limit = min(
                                self.max_threads,
                                self.active_limit + 3
                            )

                        next_sample = now + 2

                    if self.stop_event.is_set():
                        for future in futures:
                            future.cancel()

                    while (
                        not self.stop_event.is_set()
                        and not exhausted
                        and len(futures) < self.active_limit
                        and now >= next_submit
                    ):
                        row = domain_cursor.fetchone()

                        if row is None:
                            exhausted = True
                            break

                        future = executor.submit(
                            self.check_domain,
                            row[0]
                        )
                        futures[future] = row[0]

                        if self.qps > 0:
                            next_submit = time.monotonic() + 1 / self.qps
                            break

                    if not futures:
                        if self.stop_event.is_set() or exhausted:
                            break

                    completed, _ = wait(
                        futures,
                        timeout=0.2,
                        return_when=FIRST_COMPLETED
                    )

                    for future in completed:
                        futures.pop(future, None)

                        if future.cancelled():
                            continue

                        domain, success = future.result()
                        self.done += 1

                        if success:
                            connection.execute(
                                "INSERT OR IGNORE INTO results VALUES (?)",
                                (domain,)
                            )
                            self.success += 1

                    connection.commit()

                    self.signals.progress.emit(
                        self.done,
                        self.total,
                        self.success,
                        cpu_usage,
                        ram_usage,
                        len(futures),
                        self.active_limit
                    )

                    if exhausted and not futures:
                        break

                    if self.stop_event.is_set() and not futures:
                        break

            finally:
                executor.shutdown(wait=True, cancel_futures=True)

            self.export_results(connection)
            connection.close()

            self.signals.finished.emit(
                "Cancelled" if self.stop_event.is_set() else "Completed"
            )

        except Exception as error:
            self.signals.error.emit(str(error))

        finally:
            if database_path and os.path.exists(database_path):
                try:
                    os.remove(database_path)
                except OSError:
                    pass


class DNSCheckerGUI(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("DNS Checker")
        self.resize(1000, 750)

        self.signals = WorkerSignals()
        self.stop_event = threading.Event()
        self.worker_thread = None
        self.worker_rows = {}

        self.signals.stage.connect(self.update_stage)
        self.signals.progress.connect(self.update_progress)
        self.signals.worker_update.connect(self.update_worker)
        self.signals.finished.connect(self.finished)
        self.signals.error.connect(self.show_error)

        self.build_ui()

    def build_ui(self):
        root = QWidget()
        layout = QVBoxLayout(root)

        files_group = QGroupBox("Files")
        files_layout = QGridLayout(files_group)

        self.input_path = QLineEdit()
        self.output_path = QLineEdit()

        input_button = QPushButton("Browse")
        output_button = QPushButton("Browse")

        input_button.clicked.connect(self.select_input)
        output_button.clicked.connect(self.select_output)

        files_layout.addWidget(QLabel("Input file:"), 0, 0)
        files_layout.addWidget(self.input_path, 0, 1)
        files_layout.addWidget(input_button, 0, 2)
        files_layout.addWidget(QLabel("Output file:"), 1, 0)
        files_layout.addWidget(self.output_path, 1, 1)
        files_layout.addWidget(output_button, 1, 2)

        settings_group = QGroupBox("Settings")
        settings_layout = QGridLayout(settings_group)

        self.dns_input = QLineEdit("8.8.8.8")
        self.min_threads = self.create_spinbox(1, 200, 6)
        self.max_threads = self.create_spinbox(1, 200, 200)
        self.cpu_limit = self.create_spinbox(1, 100, 70)
        self.ram_limit = self.create_spinbox(1, 100, 75)
        self.timeout = self.create_spinbox(1, 60, 15)
        self.qps = self.create_spinbox(0, 100000, 0)

        settings = [
            ("DNS servers:", self.dns_input),
            ("Minimum threads:", self.min_threads),
            ("Maximum threads:", self.max_threads),
            ("Maximum CPU (%):", self.cpu_limit),
            ("Maximum RAM (%):", self.ram_limit),
            ("Timeout (sec.):", self.timeout),
            ("Max. DNS queries/sec. (0 = unlimited):", self.qps)
        ]

        for index, (label, widget) in enumerate(settings):
            row = index // 2
            column = (index % 2) * 2
            settings_layout.addWidget(QLabel(label), row, column)
            settings_layout.addWidget(widget, row, column + 1)

        controls = QHBoxLayout()

        self.start_button = QPushButton("Start")
        self.stop_button = QPushButton("Stop")
        self.stop_button.setEnabled(False)

        self.start_button.clicked.connect(self.start_check)
        self.stop_button.clicked.connect(self.stop_check)

        controls.addWidget(self.start_button)
        controls.addWidget(self.stop_button)

        self.stage_label = QLabel("Ready")
        self.progress_bar = QProgressBar()

        self.stats_label = QLabel(
            "Checked: 0 | Successful: 0 | CPU: 0 % | RAM: 0 % | Active queries: 0"
        )

        self.worker_table = QTableWidget(0, 3)
        self.worker_table.setHorizontalHeaderLabels(
            ["Worker", "Domain", "Status"]
        )
        self.worker_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Stretch
        )
        self.worker_table.setAlternatingRowColors(True)

        layout.addWidget(files_group)
        layout.addWidget(settings_group)
        layout.addLayout(controls)
        layout.addWidget(self.stage_label)
        layout.addWidget(self.progress_bar)
        layout.addWidget(self.stats_label)
        layout.addWidget(QLabel("Active workers"))
        layout.addWidget(self.worker_table)

        self.setCentralWidget(root)

    @staticmethod
    def create_spinbox(minimum, maximum, value):
        spinbox = QSpinBox()
        spinbox.setRange(minimum, maximum)
        spinbox.setValue(value)
        return spinbox

    def select_input(self):
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select input file",
            "",
            "Text files (*.txt);;All files (*)"
        )

        if path:
            self.input_path.setText(path)

    def select_output(self):
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Select output file",
            "dns_results.txt",
            "Text files (*.txt);;All files (*)"
        )

        if path:
            self.output_path.setText(path)

    def start_check(self):
        input_file = self.input_path.text().strip()
        output_file = self.output_path.text().strip()
        dns_servers = [
            value.strip()
            for value in self.dns_input.text().split(",")
            if value.strip()
        ]

        if not os.path.isfile(input_file):
            QMessageBox.warning(self, "Error", "Input file not found.")
            return

        if not output_file:
            QMessageBox.warning(self, "Error", "Output file is missing.")
            return

        if os.path.abspath(input_file) == os.path.abspath(output_file):
            QMessageBox.warning(
                self,
                "Error",
                "Input and output files must be different."
            )
            return

        try:
            for server in dns_servers:
                ipaddress.ip_address(server)
        except ValueError:
            QMessageBox.warning(
                self,
                "Error",
                "DNS servers must be valid IP addresses."
            )
            return

        if not dns_servers:
            QMessageBox.warning(self, "Error", "Enter at least one DNS server.")
            return

        min_threads = self.min_threads.value()
        max_threads = self.max_threads.value()

        if min_threads > max_threads:
            QMessageBox.warning(
                self,
                "Error",
                "Minimum threads cannot exceed maximum threads."
            )
            return

        self.stop_event.clear()
        self.worker_rows.clear()
        self.worker_table.setRowCount(0)
        self.progress_bar.setValue(0)
        self.stats_label.setText("Initializing...")

        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)

        checker = DNSChecker(
            input_file=input_file,
            output_file=output_file,
            dns_servers=dns_servers,
            min_threads=min_threads,
            max_threads=max_threads,
            cpu_limit=self.cpu_limit.value(),
            ram_limit=self.ram_limit.value(),
            timeout=self.timeout.value(),
            qps=self.qps.value(),
            signals=self.signals,
            stop_event=self.stop_event
        )

        self.worker_thread = threading.Thread(
            target=checker.run,
            daemon=True
        )
        self.worker_thread.start()

    def stop_check(self):
        self.stop_event.set()
        self.stage_label.setText("Stop requested...")

    def update_stage(self, message):
        self.stage_label.setText(message)

    def update_progress(
        self,
        done,
        total,
        success,
        cpu,
        ram,
        active,
        limit
    ):
        percentage = int(done / total * 100) if total else 0
        self.progress_bar.setValue(percentage)

        self.stats_label.setText(
            f"Checked: {done:,} / {total:,} | "
            f"Successful: {success:,} | "
            f"CPU: {cpu:.1f}% | "
            f"RAM: {ram:.1f}% | "
            f"Active queries: {active} | "
            f"Thread limit: {limit}"
        )

    def update_worker(self, worker, domain, status):
        if worker not in self.worker_rows:
            row = self.worker_table.rowCount()
            self.worker_table.insertRow(row)
            self.worker_rows[worker] = row

            self.worker_table.setItem(
                row, 0, QTableWidgetItem(worker)
            )
            self.worker_table.setItem(
                row, 1, QTableWidgetItem(domain)
            )
            self.worker_table.setItem(
                row, 2, QTableWidgetItem(status)
            )
        else:
            row = self.worker_rows[worker]
            self.worker_table.item(row, 1).setText(domain)
            self.worker_table.item(row, 2).setText(status)

    def finished(self, message):
        self.stage_label.setText(message)
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)

        QMessageBox.information(
            self,
            "DNS Checker",
            f"{message}\nOutput file:\n{self.output_path.text()}"
        )

    def show_error(self, message):
        self.stage_label.setText("Error")
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)

        QMessageBox.critical(
            self,
            "DNS Checker Error",
            message
        )


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = DNSCheckerGUI()
    window.show()
    sys.exit(app.exec())
