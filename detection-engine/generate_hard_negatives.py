import random
import numpy as np
import pandas as pd


# ==========================================
# CONFIGURATION
# ==========================================

INPUT_FILE = "dataset_features.csv"
OUTPUT_FILE = "dataset_augmented.csv"

NUM_HARD_NEGATIVES = 600

random.seed(42)
np.random.seed(42)


# ==========================================
# LOAD EXISTING DATA
# ==========================================

df = pd.read_csv(INPUT_FILE)

print("\n==========================================")
print("HARD-NEGATIVE DATA GENERATION")
print("==========================================")

print("Existing rows:", len(df))


# ==========================================
# GENERATE LEGITIMATE HIGH-ACTIVITY SAMPLES
# ==========================================

samples = []


for _ in range(NUM_HARD_NEGATIVES):

    scenario = random.choice([
        "backup",
        "archive",
        "file_copy",
        "photo_processing",
        "software_update",
        "bulk_rename"
    ])


    # --------------------------------------
    # Default values
    # --------------------------------------

    entropy = random.uniform(3.0, 6.5)

    rename_count = random.randint(5, 35)

    modification_count = random.randint(5, 50)

    cpu_usage = random.uniform(20, 85)

    memory_usage = random.uniform(25, 85)

    file_size = random.randint(
        10_000,
        50_000_000
    )

    suspicious_extension = 0

    time_window = random.choice([
        10,
        15,
        20,
        30,
        60
    ])


    # --------------------------------------
    # Scenario-specific behavior
    # --------------------------------------

    if scenario == "backup":

        rename_count = random.randint(
            5,
            25
        )

        modification_count = random.randint(
            10,
            45
        )

        entropy = random.uniform(
            3.5,
            6.2
        )


    elif scenario == "archive":

        rename_count = random.randint(
            3,
            20
        )

        modification_count = random.randint(
            5,
            30
        )

        entropy = random.uniform(
            4.0,
            6.8
        )

        cpu_usage = random.uniform(
            40,
            90
        )


    elif scenario == "file_copy":

        rename_count = random.randint(
            0,
            15
        )

        modification_count = random.randint(
            15,
            60
        )

        entropy = random.uniform(
            3.0,
            6.5
        )


    elif scenario == "photo_processing":

        rename_count = random.randint(
            5,
            30
        )

        modification_count = random.randint(
            10,
            40
        )

        entropy = random.uniform(
            4.0,
            6.7
        )

        cpu_usage = random.uniform(
            35,
            95
        )


    elif scenario == "software_update":

        rename_count = random.randint(
            5,
            35
        )

        modification_count = random.randint(
            15,
            70
        )

        entropy = random.uniform(
            3.0,
            6.0
        )

        cpu_usage = random.uniform(
            30,
            90
        )


    elif scenario == "bulk_rename":

        rename_count = random.randint(
            15,
            80
        )

        modification_count = random.randint(
            0,
            15
        )

        entropy = random.uniform(
            3.0,
            6.0
        )


    # --------------------------------------
    # Calculate engineered features
    # --------------------------------------

    time_window_safe = max(
        time_window,
        1
    )

    modification_rate = (
        modification_count /
        time_window_safe
    )

    rename_rate = (
        rename_count /
        time_window_safe
    )

    total_activity = (
        modification_count +
        rename_count
    )

    activity_rate = (
        total_activity /
        time_window_safe
    )

    modification_rename_ratio = (
        modification_count /
        (rename_count + 1)
    )

    entropy_risk = entropy / 8.0

    high_entropy = int(
        entropy >= 7.0
    )

    high_file_activity = int(
        total_activity >= 10
    )

    behavior_score = (
        entropy_risk +
        activity_rate +
        suspicious_extension
    )

    system_load = (
        cpu_usage * 0.7 +
        memory_usage * 0.3
    )

    log_file_size = np.log1p(
        file_size
    )


    # --------------------------------------
    # Create row
    # --------------------------------------

    samples.append({

        "Entropy": round(
            entropy,
            4
        ),

        "Rename_Count": rename_count,

        "Modification_Count":
            modification_count,

        "CPU_Usage": round(
            cpu_usage,
            2
        ),

        "Memory_Usage": round(
            memory_usage,
            2
        ),

        "File_Size": file_size,

        "Suspicious_Extension":
            suspicious_extension,

        "Time_Window":
            time_window,

        "Timestamp":
            "synthetic_hard_negative",

        "Label":
            "Normal",

        "Modification_Rate":
            round(
                modification_rate,
                4
            ),

        "Rename_Rate":
            round(
                rename_rate,
                4
            ),

        "Total_File_Activity":
            total_activity,

        "File_Activity_Rate":
            round(
                activity_rate,
                4
            ),

        "Modification_Rename_Ratio":
            round(
                modification_rename_ratio,
                4
            ),

        "Entropy_Risk":
            round(
                entropy_risk,
                4
            ),

        "High_Entropy":
            high_entropy,

        "High_File_Activity":
            high_file_activity,

        "Behavior_Score":
            round(
                behavior_score,
                4
            ),

        "System_Load":
            round(
                system_load,
                4
            ),

        "Log_File_Size":
            round(
                log_file_size,
                4
            )
    })


# ==========================================
# CREATE DATAFRAME
# ==========================================

hard_negative_df = pd.DataFrame(
    samples
)


print(
    "Generated hard-negative rows:",
    len(hard_negative_df)
)


# ==========================================
# COMBINE DATASETS
# ==========================================

augmented_df = pd.concat(
    [
        df,
        hard_negative_df
    ],
    ignore_index=True
)


# ==========================================
# REMOVE DUPLICATES
# ==========================================

before = len(augmented_df)

augmented_df = (
    augmented_df
    .drop_duplicates()
    .reset_index(drop=True)
)

removed = (
    before -
    len(augmented_df)
)


print(
    "Duplicate rows removed:",
    removed
)


# ==========================================
# SAVE
# ==========================================

augmented_df.to_csv(
    OUTPUT_FILE,
    index=False
)


# ==========================================
# RESULTS
# ==========================================

print("\n==========================================")
print("AUGMENTATION COMPLETE")
print("==========================================")

print(
    "Final rows:",
    len(augmented_df)
)

print(
    "Output:",
    OUTPUT_FILE
)

print("\nClass distribution:")

print(
    augmented_df["Label"]
    .value_counts()
)

print("\nClass percentages:")

print(
    augmented_df["Label"]
    .value_counts(
        normalize=True
    )
    .mul(100)
    .round(2)
)