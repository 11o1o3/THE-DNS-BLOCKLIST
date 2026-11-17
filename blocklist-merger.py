
import sys
import os
import sqlite3
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlsplit

import requests

from PySide6.QtCore import QObject, Signal
from PySide6.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QGridLayout,
    QLabel,
    QPushButton,
    QFileDialog,
    QLineEdit,
    QProgressBar,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QMessageBox,
    QGroupBox,
    QSpinBox,
    QTextEdit
)


def normalize_domain(value):
    """Extract and validate a domain from a blocklist line.

    :param value: Raw blocklist line.
    :return: Normalized domain or None.
    """
    value = value.strip()

    if not value or value.startswith(("#", "!", "[", "@")):
        return None

    parts = value.split()

    if len(parts) > 1:
        if parts[0] in ("0.0.0.0", "127.0.0.1", "0"):
            value = parts[1]
        else:
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

    if len(labels) < 2:
        return None

    for label in labels:
        if (
            not label
            or len(label) > 63
            or label.startswith("-")
            or label.endswith("-")
            or not all(c.isalnum() or c == "-" for c in label)
        ):
            return None

    return value


class MergerSignals(QObject):
    status = Signal(str)
    progress = Signal(int, int)
    source_update = Signal(int, str, str)
    finished = Signal(str, int, int)
    error = Signal(str)


class BlocklistMerger:
    def __init__(
        self,
        sources,
        local_files,
        output_file,
        workers,
        signals,
        stop_event
    ):
        self.sources = sources
        self.local_files = local_files
        self.output_file = output_file
        self.workers = workers
        self.signals = signals
        self.stop_event = stop_event
        self.total_lines = 0
        self.valid_domains = 0
        self.source_count = len(sources) + len(local_files)
        self.completed_sources = 0
        self.lock = threading.Lock()

    def process_lines(self, lines, connection):
        """Insert normalized domains into SQLite.

        :param lines: Iterable of raw blocklist lines.
        :param connection: SQLite connection.
        :return: Number of valid lines processed.
        """
        batch = []
        count = 0

        for line in lines:
            if self.stop_event.is_set():
                break

            domain = normalize_domain(line)

            if domain:
                batch.append((domain,))
                count += 1

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

        return count

    def download_source(self, index, url):
        """Download a remote blocklist into a temporary file.

        :param index: Source index.
        :param url: Blocklist URL.
        :return: Tuple containing index, temporary file path and error.
        """
        path = None

        try:
            self.signals.source_update.emit(index, url, "Downloading")

            descriptor, path = tempfile.mkstemp(
                prefix="blocklist_",
                suffix=".txt"
            )
            os.close(descriptor)

            with requests.get(
                url,
                stream=True,
                timeout=(15, 120),
                headers={"User-Agent": "BlocklistMerger/1.0"}
            ) as response:
                response.raise_for_status()

                with open(path, "wb") as file:
                    for chunk in response.iter_content(chunk_size=1024 * 1024):
                        if self.stop_event.is_set():
                            break

                        if chunk:
                            file.write(chunk)

            if self.stop_event.is_set():
                self.signals.source_update.emit(index, url, "Cancelled")
                return index, None, None

            self.signals.source_update.emit(index, url, "Downloaded")
            return index, path, None

        except Exception as error:
            if path and os.path.exists(path):
                os.remove(path)

            self.signals.source_update.emit(index, url, "Failed")
            return index, None, str(error)

    def import_file(self, path, connection, index, name):
        """Import a local or downloaded blocklist file.

        :param path: File path.
        :param connection: SQLite connection.
        :param index: Source index.
        :param name: Source display name.
        """
        try:
            self.signals.source_update.emit(index, name, "Importing")

            with open(
                path,
                "r",
                encoding="utf-8",
                errors="ignore"
            ) as file:
                count = self.process_lines(file, connection)

            with self.lock:
                self.total_lines += count
                self.completed_sources += 1

            self.signals.source_update.emit(index, name, "Completed")
            self.signals.progress.emit(
                self.completed_sources,
                self.source_count
            )

        except Exception as error:
            self.signals.source_update.emit(
                index,
                name,
                f"Failed: {error}"
            )

            with self.lock:
                self.completed_sources += 1

    def export_results(self, connection):
        """Export unique domains in alphabetical order.

        :param connection: SQLite connection.
        """
        self.signals.status.emit("Exporting sorted domains...")

        cursor = connection.execute(
            "SELECT domain FROM domains ORDER BY domain"
        )

        with open(self.output_file, "w", encoding="utf-8") as file:
            while True:
                rows = cursor.fetchmany(10000)

                if not rows:
                    break

                file.writelines(domain + "\n" for (domain,) in rows)

    def run(self):
        """Execute the blocklist merging process."""
        database_path = None
        temporary_files = []

        try:
            descriptor, database_path = tempfile.mkstemp(
                prefix="blocklist_merger_",
                suffix=".sqlite"
            )
            os.close(descriptor)

            connection = sqlite3.connect(database_path)
            connection.execute(
                "CREATE TABLE domains (domain TEXT PRIMARY KEY)"
            )

            self.signals.status.emit("Preparing sources...")

            downloaded = {}

            if self.sources:
                self.signals.status.emit("Downloading blocklists...")

                with ThreadPoolExecutor(
                    max_workers=self.workers
                ) as executor:
                    futures = {
                        executor.submit(
                            self.download_source,
                            index,
                            url
                        ): (index, url)
                        for index, url in enumerate(self.sources)
                    }

                    for future in as_completed(futures):
                        if self.stop_event.is_set():
                            break

                        index, path, error = future.result()

                        if path:
                            downloaded[index] = path
                            temporary_files.append(path)

            if not self.stop_event.is_set():
                self.signals.status.emit("Importing local and downloaded files...")

                tasks = []

                for index, path in enumerate(self.local_files):
                    tasks.append((index, path, path))

                offset = len(self.local_files)

                for source_index, url in enumerate(self.sources):
                    path = downloaded.get(source_index)

                    if path:
                        tasks.append((offset + source_index, path, url))

                for index, path, name in tasks:
                    if self.stop_event.is_set():
                        break

                    self.import_file(
                        path,
                        connection,
                        index,
                        name
                    )

            self.valid_domains = connection.execute(
                "SELECT COUNT(*) FROM domains"
            ).fetchone()[0]

            if not self.stop_event.is_set():
                self.export_results(connection)

            connection.close()

            if self.stop_event.is_set():
                self.signals.finished.emit(
                    "Cancelled",
                    self.valid_domains,
                    self.total_lines
                )
            else:
                self.signals.finished.emit(
                    "Completed",
                    self.valid_domains,
                    self.total_lines
                )

        except Exception as error:
            self.signals.error.emit(str(error))

        finally:
            for path in temporary_files:
                try:
                    os.remove(path)
                except OSError:
                    pass

            if database_path and os.path.exists(database_path):
                try:
                    os.remove(database_path)
                except OSError:
                    pass


class BlocklistMergerGUI(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Blocklist Merger")
        self.resize(1050, 800)

        self.signals = MergerSignals()
        self.stop_event = threading.Event()
        self.worker_thread = None
        self.local_files = []
        self.source_rows = {}

        self.signals.status.connect(self.update_status)
        self.signals.progress.connect(self.update_progress)
        self.signals.source_update.connect(self.update_source)
        self.signals.finished.connect(self.finished)
        self.signals.error.connect(self.show_error)

        self.build_ui()

    def build_ui(self):
        root = QWidget()
        layout = QVBoxLayout(root)

        sources_group = QGroupBox("Remote blocklist sources")
        sources_layout = QVBoxLayout(sources_group)

        self.sources_input = QTextEdit()
        self.sources_input.setPlaceholderText(
            "Enter one URL per line\n"
            "https://example.com/blocklist.txt"
        )
        self.sources_input.setMinimumHeight(120)

        sources_layout.addWidget(self.sources_input)

        local_group = QGroupBox("Local files")
        local_layout = QHBoxLayout(local_group)

        self.local_label = QLabel("No local files selected")
        self.local_button = QPushButton("Add files")
        self.local_button.clicked.connect(self.select_local_files)

        local_layout.addWidget(self.local_label, 1)
        local_layout.addWidget(self.local_button)

        output_group = QGroupBox("Output")
        output_layout = QGridLayout(output_group)

        self.output_path = QLineEdit()
        self.output_path.setPlaceholderText("Output file path")

        output_button = QPushButton("Browse")
        output_button.clicked.connect(self.select_output)

        output_layout.addWidget(QLabel("Output file:"), 0, 0)
        output_layout.addWidget(self.output_path, 0, 1)
        output_layout.addWidget(output_button, 0, 2)

        settings_group = QGroupBox("Settings")
        settings_layout = QGridLayout(settings_group)

        self.workers = QSpinBox()
        self.workers.setRange(1, 32)
        self.workers.setValue(8)

        settings_layout.addWidget(QLabel("Download threads:"), 0, 0)
        settings_layout.addWidget(self.workers, 0, 1)

        controls = QHBoxLayout()

        self.start_button = QPushButton("Start")
        self.stop_button = QPushButton("Stop")
        self.stop_button.setEnabled(False)

        self.start_button.clicked.connect(self.start_merger)
        self.stop_button.clicked.connect(self.stop_merger)

        controls.addWidget(self.start_button)
        controls.addWidget(self.stop_button)

        self.status_label = QLabel("Ready")
        self.progress_bar = QProgressBar()

        self.stats_label = QLabel(
            "Unique domains: 0 | Processed lines: 0"
        )

        self.source_table = QTableWidget(0, 3)
        self.source_table.setHorizontalHeaderLabels(
            ["Source", "Location", "Status"]
        )
        self.source_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Stretch
        )
        self.source_table.setAlternatingRowColors(True)

        layout.addWidget(sources_group)
        layout.addWidget(local_group)
        layout.addWidget(output_group)
        layout.addWidget(settings_group)
        layout.addLayout(controls)
        layout.addWidget(self.status_label)
        layout.addWidget(self.progress_bar)
        layout.addWidget(self.stats_label)
        layout.addWidget(QLabel("Source status"))
        layout.addWidget(self.source_table)

        self.setCentralWidget(root)

    def select_local_files(self):
        paths, _ = QFileDialog.getOpenFileNames(
            self,
            "Select local blocklist files",
            "",
            "Text files (*.txt);;All files (*)"
        )

        if paths:
            self.local_files.extend(
                path for path in paths if path not in self.local_files
            )

            self.local_label.setText(
                f"{len(self.local_files)} local file(s) selected"
            )

    def select_output(self):
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Select output file",
            "merged_blocklist.txt",
            "Text files (*.txt);;All files (*)"
        )

        if path:
            self.output_path.setText(path)

    def start_merger(self):
        sources = [
            line.strip()
            for line in self.sources_input.toPlainText().splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]

        output_file = self.output_path.text().strip()

        if not sources and not self.local_files:
            QMessageBox.warning(
                self,
                "Error",
                "Add at least one remote source or local file."
            )
            return

        if not output_file:
            QMessageBox.warning(
                self,
                "Error",
                "Select an output file."
            )
            return

        if any(not os.path.isfile(path) for path in self.local_files):
            QMessageBox.warning(
                self,
                "Error",
                "One or more local files do not exist."
            )
            return

        output_absolute = os.path.abspath(output_file)

        if any(
            os.path.abspath(path) == output_absolute
            for path in self.local_files
        ):
            QMessageBox.warning(
                self,
                "Error",
                "The output file must not be one of the input files."
            )
            return

        self.stop_event.clear()
        self.source_rows.clear()
        self.source_table.setRowCount(0)
        self.progress_bar.setValue(0)
        self.stats_label.setText(
            "Unique domains: 0 | Processed lines: 0"
        )

        for index, path in enumerate(self.local_files):
            self.add_source_row(index, path, "Waiting")

        offset = len(self.local_files)

        for index, url in enumerate(sources):
            self.add_source_row(offset + index, url, "Waiting")

        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)

        merger = BlocklistMerger(
            sources=sources,
            local_files=self.local_files.copy(),
            output_file=output_file,
            workers=self.workers.value(),
            signals=self.signals,
            stop_event=self.stop_event
        )

        self.worker_thread = threading.Thread(
            target=merger.run,
            daemon=True
        )
        self.worker_thread.start()

    def add_source_row(self, index, name, status):
        row = self.source_table.rowCount()
        self.source_table.insertRow(row)
        self.source_rows[index] = row

        self.source_table.setItem(
            row, 0, QTableWidgetItem(str(index + 1))
        )
        self.source_table.setItem(
            row, 1, QTableWidgetItem(name)
        )
        self.source_table.setItem(
            row, 2, QTableWidgetItem(status)
        )

    def update_source(self, index, name, status):
        if index not in self.source_rows:
            self.add_source_row(index, name, status)
            return

        row = self.source_rows[index]
        self.source_table.item(row, 1).setText(name)
        self.source_table.item(row, 2).setText(status)

    def update_status(self, message):
        self.status_label.setText(message)

    def update_progress(self, done, total):
        self.progress_bar.setValue(
            int(done / total * 100) if total else 0
        )

    def finished(self, message, unique_domains, processed_lines):
        self.status_label.setText(message)
        self.stats_label.setText(
            f"Unique domains: {unique_domains:,} | "
            f"Processed valid lines: {processed_lines:,}"
        )

        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)

        QMessageBox.information(
            self,
            "Blocklist Merger",
            f"{message}\n"
            f"Unique domains: {unique_domains:,}\n"
            f"Processed valid lines: {processed_lines:,}\n"
            f"Output file:\n{self.output_path.text()}"
        )

    def show_error(self, message):
        self.status_label.setText("Error")
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)

        QMessageBox.critical(
            self,
            "Blocklist Merger Error",
            message
        )

    def stop_merger(self):
        self.stop_event.set()
        self.status_label.setText("Stop requested...")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = BlocklistMergerGUI()
    window.show()
    sys.exit(app.exec())
