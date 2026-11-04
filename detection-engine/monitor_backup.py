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

MODEL_PATH = "ransomware_production_model.pkl"

MONITOR_PATH = "demo_folder"

API_URL = "http://127.0.0.1:8000/detection/update"

RUNTIME_DATASET = "runtime_detections.csv"

TIME_WINDOW = 15

# Security-oriented threshold selected from threshold analysis
RANSOMWARE_THRESHOLD = 0.60

SUSPICIOUS_EXTENSIONS = [
    ".locked",
    ".encrypted",
    ".crypt",
    ".crypto",
    ".enc",
]


# ============================================================
# LOAD PRODUCTION MODEL
# ============================================================

print("\n==========================================")
print("AI RANSOMWARE DETECTION ENGINE")
print("==========================================")

try:
    model = joblib.load(MODEL_PATH)
    print(f"Production model loaded: {MODEL_PATH}")
except FileNotFoundError:
    print(f"\nERROR: {MODEL_PATH} not found.")
    print("Run train_production_model.py first.")
    raise SystemExit(1)
except Exception as error:
    print("\nERROR loading model:", error)
    raise SystemExit(1)


# ============================================================
# ENTROPY
# ============================================================

def calculate_entropy(file_path):

    try:

        with open(file_path, "rb") as file:
            data = file.read()

        if len(data) == 0:
            return 0.0

        byte_counts = np.bincount(
            np.frombuffer(data, dtype=np.uint8),
            minlength=256
        )

        probabilities = (
            byte_counts[byte_counts > 0] / len(data)
        )

        entropy = -np.sum(
            probabilities * np.log2(probabilities)
        )

        return round(float(entropy), 4)

    except (FileNotFoundError, PermissionError, OSError):
        return 0.0

    except Exception as error:
        print("Entropy error:", error)
        return 0.0


# ============================================================
# SYSTEM METRICS
# ============================================================

def get_cpu_usage():

    try:
        return round(
            psutil.cpu_percent(interval=0.1),
            2
        )

    except Exception:
        return 0.0


def get_memory_usage():

    try:
        return round(
            psutil.virtual_memory().percent,
            2
        )

    except Exception:
        return 0.0


# ============================================================
# DATASET INITIALIZATION
# ============================================================

def initialize_runtime_dataset():

    if not os.path.exists(RUNTIME_DATASET):

        with open(
            RUNTIME_DATASET,
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
                "Prediction",
                "Normal_Probability",
                "Ransomware_Probability",
                "Alert",
                "File",
                "Timestamp"
            ])

        print(
            f"Runtime dataset created: "
            f"{RUNTIME_DATASET}"
        )


# ============================================================
# SAVE DETECTION
# ============================================================

def save_detection(
    features,
    prediction,
    probabilities,
    alert,
    file_path
):

    try:

        with open(
            RUNTIME_DATASET,
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
                prediction,
                probabilities.get("Normal", 0.0),
                probabilities.get("Ransomware", 0.0),
                alert,
                file_path,
                time.strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
            ])

    except Exception as error:

        print(
            "Dataset save error:",
            error
        )


# ============================================================
# SEND DETECTION TO API
# ============================================================

def send_detection_to_api(
    prediction,
    probabilities,
    alert,
    file_path
):

    payload = {

        "prediction": prediction,

        "normal_probability": round(
            probabilities.get("Normal", 0.0),
            4
        ),

        "ransomware_probability": round(
            probabilities.get("Ransomware", 0.0),
            4
        ),

        "alert": bool(alert),

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

            print(
                "Detection sent to API successfully."
            )

        else:

            print(
                "API returned status:",
                response.status_code
            )

    except requests.exceptions.ConnectionError:

        print(
            "API unavailable. "
            "Detection was still logged locally."
        )

    except requests.exceptions.Timeout:

        print(
            "API request timed out."
        )

    except Exception as error:

        print(
            "API error:",
            error
        )


# ============================================================
# FILE MONITOR
# ============================================================

class MonitorHandler(FileSystemEventHandler):

    def __init__(self):

        super().__init__()

        self.rename_count = 0

        self.modification_count = 0

        self.start_time = time.time()

        # Prevent duplicate processing
        self.recent_events = {}

        print(
            "Monitoring handler initialized."
        )


    # ========================================================
    # IGNORE FILES
    # ========================================================

    def ignore_file(self, path):

        if not path:
            return True

        ignored_files = [
            "desktop.ini",
            "thumbs.db"
        ]

        filename = os.path.basename(
            path
        ).lower()

        if filename in ignored_files:
            return True

        # Ignore our own runtime dataset
        if filename == RUNTIME_DATASET.lower():
            return True

        return False


    # ========================================================
    # RESET WINDOW
    # ========================================================

    def reset_window_if_needed(self):

        current_time = time.time()

        elapsed = (
            current_time -
            self.start_time
        )

        if elapsed > TIME_WINDOW:

            self.rename_count = 0

            self.modification_count = 0

            self.start_time = current_time

            print(
                "\nMonitoring window reset."
            )


    # ========================================================
    # SUSPICIOUS EXTENSION
    # ========================================================

    def is_suspicious_extension(
        self,
        file_path
    ):

        path_lower = file_path.lower()

        return int(
            any(
                path_lower.endswith(extension)
                for extension
                in SUSPICIOUS_EXTENSIONS
            )
        )


    # ========================================================
    # DUPLICATE EVENT PROTECTION
    # ========================================================

    def is_duplicate_event(
        self,
        file_path,
        event_type
    ):

        current_time = time.time()

        key = (
            os.path.normcase(
                os.path.abspath(file_path)
            ),
            event_type
        )

        last_time = self.recent_events.get(
            key,
            0
        )

        # Ignore identical event within 0.5 sec
        if current_time - last_time < 0.5:

            return True

        self.recent_events[key] = current_time

        # Remove old entries
        expired = [
            k
            for k, timestamp
            in self.recent_events.items()
            if current_time - timestamp > 10
        ]

        for k in expired:
            del self.recent_events[k]

        return False


    # ========================================================
    # PROCESS ACTIVITY
    # ========================================================

    def process_activity(
        self,
        file_path
    ):

        self.reset_window_if_needed()

        # File may have disappeared after event
        if not os.path.exists(file_path):

            print(
                "File no longer exists:",
                file_path
            )

            return

        # Small delay to allow Windows file operation
        # to complete
        time.sleep(0.1)

        entropy = calculate_entropy(
            file_path
        )

        try:

            file_size = os.path.getsize(
                file_path
            )

        except (
            FileNotFoundError,
            PermissionError,
            OSError
        ):

            file_size = 0

        cpu_usage = get_cpu_usage()

        memory_usage = get_memory_usage()

        suspicious_extension = (
            self.is_suspicious_extension(
                file_path
            )
        )

        # ====================================================
        # EXACT 8 FEATURES USED BY PRODUCTION MODEL
        # ====================================================

        features = {

            "Entropy":
                entropy,

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

        print("\n==========================================")
        print("FILE ACTIVITY DETECTED")
        print("==========================================")

        print(
            "File:",
            file_path
        )

        print("\nFEATURES")

        for key, value in features.items():

            print(
                f"{key}: {value}"
            )


        # ====================================================
        # MODEL PREDICTION
        # ====================================================

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

        try:

            probabilities_array = (
                model.predict_proba(
                    input_data
                )[0]
            )

            probability_map = {}

            for class_name, probability in zip(
                model.classes_,
                probabilities_array
            ):

                probability_map[
                    str(class_name)
                ] = float(probability)

            normal_probability = (
                probability_map.get(
                    "Normal",
                    0.0
                )
            )

            ransomware_probability = (
                probability_map.get(
                    "Ransomware",
                    0.0
                )
            )

            # =================================================
            # SECURITY-ORIENTED THRESHOLD
            # =================================================

            if (
                ransomware_probability
                >= RANSOMWARE_THRESHOLD
            ):

                prediction = "Ransomware"

            else:

                prediction = "Normal"

        except Exception as error:

            print(
                "\nPrediction error:",
                error
            )

            return


        alert = (
            prediction == "Ransomware"
        )


        # ====================================================
        # OUTPUT
        # ====================================================

        print("\nAI PREDICTION")
        print("------------------------------------------")

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
            "Threshold:",
            RANSOMWARE_THRESHOLD
        )


        # ====================================================
        # SAVE LOCALLY
        # ====================================================

        save_detection(
            features,
            prediction,
            {
                "Normal":
                    normal_probability,

                "Ransomware":
                    ransomware_probability
            },
            alert,
            file_path
        )

        print(
            "Detection saved locally."
        )


        # ====================================================
        # SEND TO API
        # ====================================================

        send_detection_to_api(
            prediction,
            {
                "Normal":
                    normal_probability,

                "Ransomware":
                    ransomware_probability
            },
            alert,
            file_path
        )


        # ====================================================
        # ALERT
        # ====================================================

        if alert:

            print(
                "\n🚨 RANSOMWARE ALERT!"
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
                "------------------------------------------"
            )

        else:

            print(
                "\n✅ Activity appears normal."
            )

            print(
                "------------------------------------------"
            )


    # ========================================================
    # FILE MODIFIED
    # ========================================================

    def on_modified(self, event):

        if event.is_directory:
            return

        path = event.src_path

        if self.ignore_file(path):
            return

        if self.is_duplicate_event(
            path,
            "modified"
        ):

            return

        self.reset_window_if_needed()

        self.modification_count += 1

        print(
            "\nModified:",
            path
        )

        self.process_activity(
            path
        )


    # ========================================================
    # FILE RENAMED / MOVED
    # ========================================================

    def on_moved(self, event):

        if event.is_directory:
            return

        source_path = event.src_path

        destination_path = event.dest_path

        if self.ignore_file(
            source_path
        ):

            return

        if self.ignore_file(
            destination_path
        ):

            return

        if self.is_duplicate_event(
            destination_path,
            "moved"
        ):

            return

        self.reset_window_if_needed()

        self.rename_count += 1

        print(
            "\nRenamed:"
        )

        print(
            source_path
        )

        print(
            "->",
            destination_path
        )

        # Analyze destination because this is
        # the resulting file
        self.process_activity(
            destination_path
        )


# ============================================================
# MAIN
# ============================================================

def main():

    initialize_runtime_dataset()

    if not os.path.exists(
        MONITOR_PATH
    ):

        os.makedirs(
            MONITOR_PATH
        )

        print(
            "Created monitoring folder:",
            MONITOR_PATH
        )

    event_handler = MonitorHandler()

    observer = Observer()

    observer.schedule(
        event_handler,
        path=MONITOR_PATH,
        recursive=True
    )

    print("\n==========================================")
    print("AI RANSOMWARE MONITOR STARTED")
    print("==========================================")

    print(
        "Monitoring:",
        os.path.abspath(
            MONITOR_PATH
        )
    )

    print(
        "Model:",
        MODEL_PATH
    )

    print(
        "Threshold:",
        RANSOMWARE_THRESHOLD
    )

    print(
        "API:",
        API_URL
    )

    print(
        "\nPress CTRL + C to stop."
    )

    print(
        "==========================================\n"
    )

    observer.start()

    try:

        while True:

            time.sleep(1)

    except KeyboardInterrupt:

        print(
            "\nStopping monitor..."
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