import csv
import random
import os
from datetime import datetime, timedelta


# ============================================================
# CONFIGURATION
# ============================================================

DATASET_FILE = "dataset.csv"

NORMAL_SAMPLES = 150
RANSOMWARE_SAMPLES = 150


# ============================================================
# DATASET HEADER
# ============================================================

HEADERS = [
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
]


# ============================================================
# NORMAL ACTIVITY GENERATOR
# ============================================================

def generate_normal_sample(timestamp):
    """
    Generate a synthetic normal file activity record.
    """

    entropy = round(random.uniform(2.5, 6.8), 4)

    rename_count = random.randint(0, 2)

    modification_count = random.randint(0, 5)

    cpu_usage = round(random.uniform(5, 55), 2)

    memory_usage = round(random.uniform(30, 85), 2)

    file_size = random.choice([
        512,
        1024,
        2048,
        4096,
        8192,
        16384,
        32768,
        65536
    ])

    suspicious_extension = 0

    time_window = random.choice([
        15,
        20,
        30,
        60
    ])

    return [
        entropy,
        rename_count,
        modification_count,
        cpu_usage,
        memory_usage,
        file_size,
        suspicious_extension,
        time_window,
        timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        "Normal"
    ]


# ============================================================
# RANSOMWARE ACTIVITY GENERATOR
# ============================================================

def generate_ransomware_sample(timestamp):
    """
    Generate a synthetic ransomware-like activity record.

    IMPORTANT:
    This does NOT encrypt files.
    It only generates ML training data.
    """

    entropy = round(random.uniform(7.1, 8.0), 4)

    rename_count = random.randint(3, 15)

    modification_count = random.randint(10, 50)

    cpu_usage = round(random.uniform(20, 95), 2)

    memory_usage = round(random.uniform(50, 98), 2)

    file_size = random.choice([
        1024,
        2048,
        4096,
        8192,
        16384,
        32768,
        65536
    ])

    suspicious_extension = 1

    time_window = random.choice([
        10,
        15,
        20,
        30
    ])

    return [
        entropy,
        rename_count,
        modification_count,
        cpu_usage,
        memory_usage,
        file_size,
        suspicious_extension,
        time_window,
        timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        "Ransomware"
    ]


# ============================================================
# GENERATE DATASET
# ============================================================

def generate_dataset():

    rows = []

    start_time = datetime.now()

    # --------------------------------------------------------
    # Generate Normal samples
    # --------------------------------------------------------

    for i in range(NORMAL_SAMPLES):

        timestamp = start_time + timedelta(
            seconds=i * random.randint(5, 20)
        )

        row = generate_normal_sample(timestamp)

        rows.append(row)

    # --------------------------------------------------------
    # Generate Ransomware samples
    # --------------------------------------------------------

    for i in range(RANSOMWARE_SAMPLES):

        timestamp = start_time + timedelta(
            seconds=(NORMAL_SAMPLES + i) * random.randint(5, 20)
        )

        row = generate_ransomware_sample(timestamp)

        rows.append(row)

    # --------------------------------------------------------
    # Shuffle dataset
    # --------------------------------------------------------

    random.shuffle(rows)

    # --------------------------------------------------------
    # Save CSV
    # --------------------------------------------------------

    with open(DATASET_FILE, "w", newline="") as file:

        writer = csv.writer(file)

        writer.writerow(HEADERS)

        writer.writerows(rows)

    # --------------------------------------------------------
    # Display results
    # --------------------------------------------------------

    print()
    print("=" * 60)
    print("DATASET GENERATION COMPLETE")
    print("=" * 60)

    print(f"Dataset file : {os.path.abspath(DATASET_FILE)}")
    print(f"Normal rows  : {NORMAL_SAMPLES}")
    print(f"Ransomware rows : {RANSOMWARE_SAMPLES}")
    print(f"Total rows   : {NORMAL_SAMPLES + RANSOMWARE_SAMPLES}")

    print()
    print("Labels:")
    print("Normal      =", NORMAL_SAMPLES)
    print("Ransomware  =", RANSOMWARE_SAMPLES)

    print()
    print("Dataset columns:")

    for column in HEADERS:
        print("-", column)

    print()
    print("Dataset ready for ML training.")
    print("=" * 60)


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":
    generate_dataset()