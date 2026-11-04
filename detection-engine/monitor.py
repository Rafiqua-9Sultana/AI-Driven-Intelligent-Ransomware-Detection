import os
import time
import csv
import joblib
import psutil
import numpy as np
import pandas as pd
import requests

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


# ============================================================
# CONFIGURATION
# ============================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

MODEL_PATH = os.path.join(
    BASE_DIR,
    "ransomware_production_model.pkl"
)

DATASET_PATH = os.path.join(
    BASE_DIR,
    "dataset.csv"
)

MONITOR_PATH = os.path.join(
    BASE_DIR,
    "demo_folder"
)

API_URL = "http://127.0.0.1:8000/detection/update"

TIME_WINDOW = 15

# Security-oriented threshold obtained from threshold analysis
SECURITY_THRESHOLD = 0.60

SUSPICIOUS_EXTENSIONS = [
    ".locked",
    ".encrypted",
    ".crypt",
    ".crypto",
    ".enc",
]


# ============================================================
# STARTUP
# ============================================================

print("=" * 55)
print("AI RANSOMWARE DETECTION ENGINE")
print("=" * 55)
print()
print("Loading production model...")


# ============================================================
# LOAD PRODUCTION MODEL
# ============================================================

try:
    model = joblib.load(MODEL_PATH)

    print("✓ Production model loaded")
    print("  Model:", MODEL_PATH)

except FileNotFoundError:
    print("✗ Production model not found:")
    print(MODEL_PATH)
    print()
    print("Run train_production_model.py first.")
    raise SystemExit(1)

except Exception as error:
    print("✗ Failed to load production model:")
    print(error)
    raise SystemExit(1)


# ============================================================
# VERIFY MODEL
# ============================================================

print()
print("Model classes:", model.classes_)

if not hasattr(model, "predict_proba"):
    print("✗ ERROR: Model does not support probability prediction.")
    raise SystemExit(1)


# ============================================================
# ENTROPY CALCULATION
# ============================================================

def calculate_entropy(file_path):

    try:

        with open(file_path, "rb") as file:
            data = file.read()

        if len(data) == 0:
            return 0.0

        byte_counts = np.bincount(
            np.frombuffer(
                data,
                dtype=np.uint8
            ),
            minlength=256
        )

        probabilities = (
            byte_counts[byte_counts > 0]
            / len(data)
        )

        entropy = -np.sum(
            probabilities
            * np.log2(probabilities)
        )

        return round(float(entropy), 4)

    except Exception as error:

        print("Entropy error:", error)

        return 0.0


# ============================================================
# SYSTEM METRICS
# ============================================================

def get_cpu_usage():

    return round(
        psutil.cpu_percent(interval=0.1),
        2
    )


def get_memory_usage():

    return round(
        psutil.virtual_memory().percent,
        2
    )


# ============================================================
# DATASET INITIALIZATION
# ============================================================

def initialize_dataset():

    if not os.path.exists(DATASET_PATH):

        with open(
            DATASET_PATH,
            "w",
            newline="",
            encoding="utf-8"
        ) as file:

            writer = csv.writer(file)

            writer.writerow([
                "Entropy",
                "Rename_Count",
                "Modification_Count",
                "CPU_Usage",
                "Memory_Usage",
                "File_Size",
                "Suspicious_Extension",
                "Time_Window",
                "Timestamp",
                "Label"
            ])

        print("✓ Dataset created:")
        print(DATASET_PATH)


# ============================================================
# SAVE MONITORING DATA
# ============================================================

def save_data(features, label):

    try:

        with open(
            DATASET_PATH,
            "a",
            newline="",
            encoding="utf-8"
        ) as file:

            writer = csv.writer(file)

            writer.writerow([
                features["Entropy"],
                features["Rename_Count"],
                features["Modification_Count"],
                features["CPU_Usage"],
                features["Memory_Usage"],
                features["File_Size"],
                features["Suspicious_Extension"],
                features["Time_Window"],
                time.strftime("%Y-%m-%d %H:%M:%S"),
                label
            ])

        print("✓ Dataset row saved")

    except Exception as error:

        print("✗ Dataset save error:", error)


# ============================================================
# AI PREDICTION
# ============================================================

def predict_activity(features):

    feature_order = [
        "Entropy",
        "Rename_Count",
        "Modification_Count",
        "CPU_Usage",
        "Memory_Usage",
        "File_Size",
        "Suspicious_Extension",
        "Time_Window"
    ]

    input_data = pd.DataFrame(
        [
            [
                features[column]
                for column in feature_order
            ]
        ],
        columns=feature_order
    )

    # Model prediction
    raw_prediction = model.predict(input_data)[0]

    # Probability prediction
    probabilities = model.predict_proba(input_data)[0]

    normal_probability = 0.0
    ransomware_probability = 0.0

    # Production model:
    # class 0 = Normal
    # class 1 = Ransomware

    for class_name, probability in zip(
        model.classes_,
        probabilities
    ):

        if int(class_name) == 0:

            normal_probability = float(probability)

        elif int(class_name) == 1:

            ransomware_probability = float(probability)

    # IMPORTANT:
    # Detection decision is based on the ransomware
    # probability and security threshold.

    if ransomware_probability >= SECURITY_THRESHOLD:

        prediction = "Ransomware"

    else:

        prediction = "Normal"

    return (
        prediction,
        normal_probability,
        ransomware_probability
    )


# ============================================================
# SEND DETECTION TO API
# ============================================================

def send_detection_to_api(
    prediction,
    normal_probability,
    ransomware_probability,
    file_path
):

    alert = (
        ransomware_probability
        >= SECURITY_THRESHOLD
    )

    payload = {
        "prediction": prediction,
        "normal_probability": round(
            normal_probability,
            4
        ),
        "ransomware_probability": round(
            ransomware_probability,
            4
        ),
        "alert": alert,
        "file": file_path,
        "timestamp": time.strftime(
            "%Y-%m-%dT%H:%M:%S"
        )
    }

    try:

        response = requests.post(
            API_URL,
            json=payload,
            timeout=3
        )

        if response.status_code in [200, 201]:

            print("✓ Detection sent to API successfully.")

        else:

            print(
                "⚠ API returned:",
                response.status_code
            )

            print(
                "Response:",
                response.text
            )

    except requests.exceptions.ConnectionError:

        print(
            "⚠ API connection failed."
        )

        print(
            "Make sure FastAPI is running:"
        )

        print(
            "python -m uvicorn main:app --reload"
        )

    except requests.exceptions.Timeout:

        print("⚠ API request timed out.")

    except Exception as error:

        print(
            "⚠ API error:",
            error
        )


# ============================================================
# FILE MONITOR HANDLER
# ============================================================

class MonitorHandler(FileSystemEventHandler):

    def __init__(self):

        super().__init__()

        self.rename_count = 0

        self.modification_count = 0

        self.start_time = time.time()


    # --------------------------------------------------------
    # IGNORE FILES
    # --------------------------------------------------------

    def ignore_file(self, path):

        ignored_files = [
            "desktop.ini",
            "thumbs.db",
            ".ds_store"
        ]

        filename = os.path.basename(
            path
        ).lower()

        return filename in ignored_files


    # --------------------------------------------------------
    # RESET TIME WINDOW
    # --------------------------------------------------------

    def reset_window_if_needed(self):

        current_time = time.time()

        elapsed_time = (
            current_time
            - self.start_time
        )

        if elapsed_time > TIME_WINDOW:

            self.rename_count = 0

            self.modification_count = 0

            self.start_time = current_time

            print()
            print(
                "⟳ Monitoring window reset."
            )
            print()


    # --------------------------------------------------------
    # SUSPICIOUS EXTENSION
    # --------------------------------------------------------

    def is_suspicious_extension(
        self,
        file_path
    ):

        file_path = file_path.lower()

        return int(
            any(
                file_path.endswith(
                    extension
                )
                for extension
                in SUSPICIOUS_EXTENSIONS
            )
        )


    # --------------------------------------------------------
    # PROCESS FILE ACTIVITY
    # --------------------------------------------------------

    def process_activity(
        self,
        file_path
    ):

        self.reset_window_if_needed()

        # Give the filesystem operation a moment
        time.sleep(0.1)

        # ----------------------------------------------------
        # File information
        # ----------------------------------------------------

        entropy = calculate_entropy(
            file_path
        )

        try:

            file_size = os.path.getsize(
                file_path
            )

        except OSError:

            file_size = 0

        cpu_usage = get_cpu_usage()

        memory_usage = get_memory_usage()

        suspicious_extension = (
            self.is_suspicious_extension(
                file_path
            )
        )

        # ----------------------------------------------------
        # Feature vector
        # ----------------------------------------------------

        features = {

            "Entropy": entropy,

            "Rename_Count":
                self.rename_count,

            "Modification_Count":
                self.modification_count,

            "CPU_Usage":
                cpu_usage,

            "Memory_Usage":
                memory_usage,

            "File_Size":
                file_size,

            "Suspicious_Extension":
                suspicious_extension,

            "Time_Window":
                TIME_WINDOW
        }

        # ----------------------------------------------------
        # Display features
        # ----------------------------------------------------

        print()
        print("-" * 55)
        print("FEATURES DETECTED")
        print("-" * 55)

        for key, value in features.items():

            print(
                f"{key}: {value}"
            )

        # ----------------------------------------------------
        # AI prediction
        # ----------------------------------------------------

        (
            prediction,
            normal_probability,
            ransomware_probability
        ) = predict_activity(
            features
        )

        print()
        print("AI PREDICTION")
        print("-" * 55)

        print(
            "Prediction:",
            prediction
        )

        print(
            "Normal probability:",
            round(
                normal_probability,
                4
            )
        )

        print(
            "Ransomware probability:",
            round(
                ransomware_probability,
                4
            )
        )

        print(
            "Security threshold:",
            SECURITY_THRESHOLD
        )

        # ----------------------------------------------------
        # Save monitoring data
        # ----------------------------------------------------

        save_data(
            features,
            prediction
        )

        # ----------------------------------------------------
        # Send result to API
        # ----------------------------------------------------

        send_detection_to_api(
            prediction,
            normal_probability,
            ransomware_probability,
            file_path
        )

        # ----------------------------------------------------
        # Security alert
        # ----------------------------------------------------

        if ransomware_probability >= SECURITY_THRESHOLD:

            print()
            print(
                "🚨 RANSOMWARE ALERT!"
            )

            print(
                "Suspicious activity detected:"
            )

            print(
                file_path
            )

            print(
                "Ransomware probability:",
                f"{ransomware_probability:.2%}"
            )

            print(
                "Threshold:",
                f"{SECURITY_THRESHOLD:.0%}"
            )

            print("-" * 55)

        else:

            print()
            print(
                "✅ Activity appears normal."
            )

            print("-" * 55)


    # ========================================================
    # FILE CREATED
    # ========================================================

    def on_created(self, event):

        if event.is_directory:

            return

        if self.ignore_file(
            event.src_path
        ):

            return

        print()
        print(
            "Created:",
            event.src_path
        )

        self.process_activity(
            event.src_path
        )


    # ========================================================
    # FILE MODIFIED
    # ========================================================

    def on_modified(self, event):

        if event.is_directory:

            return

        if self.ignore_file(
            event.src_path
        ):

            return

        self.reset_window_if_needed()

        self.modification_count += 1

        print()
        print(
            "Modified:",
            event.src_path
        )

        self.process_activity(
            event.src_path
        )


    # ========================================================
    # FILE RENAMED / MOVED
    # ========================================================

    def on_moved(self, event):

        if event.is_directory:

            return

        if self.ignore_file(
            event.dest_path
        ):

            return

        self.reset_window_if_needed()

        self.rename_count += 1

        print()
        print(
            "Renamed:"
        )

        print(
            event.src_path,
            "->",
            event.dest_path
        )

        # Use destination because it represents
        # the file after the rename.

        self.process_activity(
            event.dest_path
        )


    # ========================================================
    # FILE DELETED
    # ========================================================

    def on_deleted(self, event):

        if event.is_directory:

            return

        if self.ignore_file(
            event.src_path
        ):

            return

        print()
        print(
            "Deleted:",
            event.src_path
        )


# ============================================================
# MAIN
# ============================================================

def main():

    initialize_dataset()

    # Create monitoring folder if necessary

    if not os.path.exists(
        MONITOR_PATH
    ):

        os.makedirs(
            MONITOR_PATH
        )

        print(
            "Created monitoring folder:"
        )

        print(
            MONITOR_PATH
        )

    # --------------------------------------------------------
    # Handler
    # --------------------------------------------------------

    event_handler = MonitorHandler()

    # --------------------------------------------------------
    # Watchdog observer
    # --------------------------------------------------------

    observer = Observer()

    observer.schedule(
        event_handler,
        path=MONITOR_PATH,
        recursive=True
    )

    # --------------------------------------------------------
    # Startup information
    # --------------------------------------------------------

    print()
    print("=" * 55)
    print("AI RANSOMWARE MONITOR STARTED")
    print("=" * 55)

    print(
        "Monitoring folder:"
    )

    print(
        MONITOR_PATH
    )

    print()

    print(
        "Production model:"
    )

    print(
        os.path.basename(
            MODEL_PATH
        )
    )

    print()

    print(
        "Security threshold:"
    )

    print(
        SECURITY_THRESHOLD
    )

    print()

    print(
        "API:"
    )

    print(
        API_URL
    )

    print()

    print(
        "Press CTRL + C to stop."
    )

    print("=" * 55)
    print()

    # --------------------------------------------------------
    # Start observer
    # --------------------------------------------------------

    observer.start()

    try:

        while True:

            time.sleep(1)

    except KeyboardInterrupt:

        print()
        print(
            "Stopping monitor..."
        )

        observer.stop()

    observer.join()

    print(
        "Monitor stopped."
    )


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    main()