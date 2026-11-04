import csv
import math
import sys
import time
from collections import Counter
from datetime import datetime
from pathlib import Path
from threading import Lock

import psutil
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer


# --------------------------------------------------
# PROJECT PATHS
# --------------------------------------------------

TRAINING_DIR = Path(__file__).resolve().parent
DETECTION_ENGINE_DIR = TRAINING_DIR.parent

MONITORED_FOLDER = DETECTION_ENGINE_DIR / "demo_folder"
DATASET_FILE = TRAINING_DIR / "dataset.csv"


# --------------------------------------------------
# DATASET CONFIGURATION
# --------------------------------------------------

CSV_COLUMNS = [
    "Entropy",
    "Rename_Count",
    "Modification_Count",
    "CPU_Usage",
    "Memory_Usage",
    "File_Size",
    "Suspicious_Extension",
    "Time_Window",
    "Timestamp",
    "Label",
]

TIME_WINDOW_SECONDS = 15

SUSPICIOUS_EXTENSIONS = {
    ".locked",
    ".encrypted",
    ".enc",
    ".crypt",
    ".crypto",
}


# --------------------------------------------------
# ENTROPY
# --------------------------------------------------

def calculate_entropy(file_path: Path) -> float:

    try:
        if not file_path.exists() or not file_path.is_file():
            return 0.0

        file_data = file_path.read_bytes()

        if not file_data:
            return 0.0

        byte_counts = Counter(file_data)
        file_size = len(file_data)

        entropy = 0.0

        for count in byte_counts.values():
            probability = count / file_size
            entropy -= probability * math.log2(probability)

        return round(entropy, 4)

    except (PermissionError, OSError):
        return 0.0


# --------------------------------------------------
# FILE SIZE
# --------------------------------------------------

def get_file_size(file_path: Path) -> int:

    try:
        if file_path.exists() and file_path.is_file():
            return file_path.stat().st_size

    except (PermissionError, OSError):
        pass

    return 0


# --------------------------------------------------
# SUSPICIOUS EXTENSION
# --------------------------------------------------

def has_suspicious_extension(file_path: Path) -> int:

    return int(
        file_path.suffix.lower()
        in SUSPICIOUS_EXTENSIONS
    )


# --------------------------------------------------
# CREATE DATASET
# --------------------------------------------------

def initialize_dataset() -> None:

    DATASET_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    if not DATASET_FILE.exists():

        with DATASET_FILE.open(
            "w",
            newline="",
            encoding="utf-8"
        ) as file:

            writer = csv.DictWriter(
                file,
                fieldnames=CSV_COLUMNS
            )

            writer.writeheader()

        print("Dataset created:", DATASET_FILE)

    else:

        print("Using existing dataset:", DATASET_FILE)


# --------------------------------------------------
# SAVE DATA
# --------------------------------------------------

def save_dataset_row(
    entropy,
    rename_count,
    modification_count,
    cpu_usage,
    memory_usage,
    file_size,
    suspicious_extension,
    label
):

    row = {
        "Entropy": entropy,
        "Rename_Count": rename_count,
        "Modification_Count": modification_count,
        "CPU_Usage": round(cpu_usage, 2),
        "Memory_Usage": round(memory_usage, 2),
        "File_Size": file_size,
        "Suspicious_Extension": suspicious_extension,
        "Time_Window": TIME_WINDOW_SECONDS,
        "Timestamp": datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        ),
        "Label": label,
    }

    with DATASET_FILE.open(
        "a",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=CSV_COLUMNS
        )

        writer.writerow(row)

    print("\nDataset row saved:")
    print(row)


# --------------------------------------------------
# COLLECTOR
# --------------------------------------------------

class DatasetCollector(FileSystemEventHandler):

    def __init__(self, label):

        super().__init__()

        self.label = label

        self.rename_count = 0
        self.modification_count = 0

        self.window_start = time.time()

        self.latest_file = None
        self.latest_entropy = 0.0
        self.latest_file_size = 0
        self.latest_suspicious_extension = 0

        self.lock = Lock()

        psutil.cpu_percent(interval=None)


    # --------------------------------------------------
    # IGNORE UNNECESSARY FILES
    # --------------------------------------------------

    @staticmethod
    def should_ignore(file_path):

        ignored_files = {
            "desktop.ini",
            "thumbs.db",
            ".ds_store",
        }

        return file_path.name.lower() in ignored_files


    # --------------------------------------------------
    # EXTRACT FEATURES
    # --------------------------------------------------

    def update_latest_file_features(
        self,
        file_path
    ):

        # Give Windows time to finish writing the file
        time.sleep(0.2)

        self.latest_file = file_path

        self.latest_entropy = calculate_entropy(
            file_path
        )

        self.latest_file_size = get_file_size(
            file_path
        )

        self.latest_suspicious_extension = (
            has_suspicious_extension(file_path)
        )


    # --------------------------------------------------
    # FILE CREATED
    # --------------------------------------------------

    def on_created(self, event):

        if event.is_directory:
            return

        file_path = Path(event.src_path)

        if self.should_ignore(file_path):
            return

        with self.lock:

            self.modification_count += 1

            self.update_latest_file_features(
                file_path
            )

        print(
            "Created:",
            file_path
        )

        self.check_time_window()


    # --------------------------------------------------
    # FILE MODIFIED
    # --------------------------------------------------

    def on_modified(self, event):

        if event.is_directory:
            return

        file_path = Path(event.src_path)

        if self.should_ignore(file_path):
            return

        with self.lock:

            self.modification_count += 1

            self.update_latest_file_features(
                file_path
            )

        print(
            "Modified:",
            file_path
        )

        self.check_time_window()


    # --------------------------------------------------
    # FILE RENAMED
    # --------------------------------------------------

    def on_moved(self, event):

        if event.is_directory:
            return

        destination_path = Path(
            event.dest_path
        )

        if self.should_ignore(destination_path):
            return

        with self.lock:

            self.rename_count += 1

            self.update_latest_file_features(
                destination_path
            )

        print(
            "Renamed:",
            Path(event.src_path).name,
            "->",
            destination_path.name
        )

        self.check_time_window()


    # --------------------------------------------------
    # FILE DELETED
    # --------------------------------------------------

    def on_deleted(self, event):

        if event.is_directory:
            return

        file_path = Path(event.src_path)

        if self.should_ignore(file_path):
            return

        with self.lock:

            self.modification_count += 1

        print(
            "Deleted:",
            file_path.name
        )

        self.check_time_window()


    # --------------------------------------------------
    # CHECK 15 SECOND WINDOW
    # --------------------------------------------------

    def check_time_window(self):

        elapsed_time = (
            time.time()
            - self.window_start
        )

        if elapsed_time >= TIME_WINDOW_SECONDS:

            self.save_current_window()


    # --------------------------------------------------
    # SAVE CURRENT WINDOW
    # --------------------------------------------------

    def save_current_window(self):

        with self.lock:

            rename_count = self.rename_count

            modification_count = (
                self.modification_count
            )

            entropy = self.latest_entropy

            file_size = self.latest_file_size

            suspicious_extension = (
                self.latest_suspicious_extension
            )

            self.rename_count = 0
            self.modification_count = 0

            self.latest_file = None
            self.latest_entropy = 0.0
            self.latest_file_size = 0

            self.latest_suspicious_extension = 0

            self.window_start = time.time()

        if (
            rename_count == 0
            and modification_count == 0
        ):
            return

        cpu_usage = psutil.cpu_percent(
            interval=0.2
        )

        memory_usage = (
            psutil.virtual_memory().percent
        )

        save_dataset_row(
            entropy,
            rename_count,
            modification_count,
            cpu_usage,
            memory_usage,
            file_size,
            suspicious_extension,
            self.label
        )


# --------------------------------------------------
# LABEL
# --------------------------------------------------

def get_collection_label():

    if len(sys.argv) >= 2:

        label = (
            sys.argv[1]
            .strip()
            .capitalize()
        )

        if label in [
            "Normal",
            "Ransomware"
        ]:

            return label

    print("\nUsage:")
    print(
        "python training/collect_data.py Normal"
    )
    print(
        "python training/collect_data.py Ransomware"
    )

    sys.exit(1)


# --------------------------------------------------
# MAIN
# --------------------------------------------------

def main():

    MONITORED_FOLDER.mkdir(
        parents=True,
        exist_ok=True
    )

    initialize_dataset()

    label = get_collection_label()

    event_handler = DatasetCollector(
        label
    )

    observer = Observer()

    observer.schedule(
        event_handler,
        str(MONITORED_FOLDER),
        recursive=True
    )

    observer.start()

    print("\nDataset collection started.")
    print(
        "Monitoring:",
        MONITORED_FOLDER
    )
    print(
        "Label:",
        label
    )
    print(
        "Collection window:",
        TIME_WINDOW_SECONDS,
        "seconds"
    )

    print(
        "\nPress Ctrl+C to stop.\n"
    )

    try:

        while True:

            time.sleep(1)

            elapsed_time = (
                time.time()
                - event_handler.window_start
            )

            if (
                elapsed_time
                >= TIME_WINDOW_SECONDS
            ):

                event_handler.save_current_window()

    except KeyboardInterrupt:

        print(
            "\nStopping dataset collection..."
        )

    finally:

        event_handler.save_current_window()

        observer.stop()

        observer.join()

        print(
            "Dataset collection stopped."
        )


# --------------------------------------------------
# RUN
# --------------------------------------------------

if __name__ == "__main__":
    main()