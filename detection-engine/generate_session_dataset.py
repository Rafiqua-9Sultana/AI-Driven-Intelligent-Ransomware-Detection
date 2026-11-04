import random
import numpy as np
import pandas as pd


# ==========================================
# CONFIGURATION
# ==========================================

OUTPUT_FILE = "session_dataset.csv"

RANDOM_STATE = 42

random.seed(RANDOM_STATE)
np.random.seed(RANDOM_STATE)


# Number of independent activity sessions
NORMAL_SESSIONS = 80
RANSOMWARE_SESSIONS = 60


# Rows generated per session
MIN_ROWS_PER_SESSION = 8
MAX_ROWS_PER_SESSION = 20


# ==========================================
# HELPER FUNCTIONS
# ==========================================

def generate_normal_activity(session_id, scenario):
    """
    Generate legitimate activity.

    Some normal sessions deliberately have
    high file activity so that they overlap
    with ransomware behavior.
    """

    rows = []

    number_of_rows = random.randint(
        MIN_ROWS_PER_SESSION,
        MAX_ROWS_PER_SESSION
    )

    for _ in range(number_of_rows):

        time_window = random.choice([
            10,
            15,
            20,
            30,
            60
        ])

        # ----------------------------------
        # Default normal behavior
        # ----------------------------------

        entropy = random.uniform(
            3.0,
            6.5
        )

        rename_count = random.randint(
            0,
            10
        )

        modification_count = random.randint(
            0,
            15
        )

        cpu_usage = random.uniform(
            10,
            70
        )

        memory_usage = random.uniform(
            20,
            75
        )

        file_size = random.randint(
            5_000,
            50_000_000
        )

        suspicious_extension = 0


        # ----------------------------------
        # Normal scenario variations
        # ----------------------------------

        if scenario == "backup":

            rename_count = random.randint(
                5,
                30
            )

            modification_count = random.randint(
                15,
                60
            )

            entropy = random.uniform(
                4.0,
                6.8
            )

            cpu_usage = random.uniform(
                30,
                85
            )


        elif scenario == "archive":

            rename_count = random.randint(
                3,
                20
            )

            modification_count = random.randint(
                10,
                45
            )

            entropy = random.uniform(
                4.5,
                7.1
            )

            cpu_usage = random.uniform(
                35,
                90
            )


        elif scenario == "bulk_copy":

            rename_count = random.randint(
                0,
                15
            )

            modification_count = random.randint(
                20,
                70
            )

            entropy = random.uniform(
                3.5,
                6.8
            )


        elif scenario == "photo_processing":

            rename_count = random.randint(
                5,
                35
            )

            modification_count = random.randint(
                10,
                50
            )

            entropy = random.uniform(
                4.0,
                7.2
            )

            cpu_usage = random.uniform(
                40,
                95
            )


        elif scenario == "software_update":

            rename_count = random.randint(
                5,
                40
            )

            modification_count = random.randint(
                20,
                80
            )

            entropy = random.uniform(
                3.0,
                6.5
            )

            cpu_usage = random.uniform(
                40,
                95
            )


        elif scenario == "bulk_rename":

            rename_count = random.randint(
                20,
                80
            )

            modification_count = random.randint(
                0,
                20
            )

            entropy = random.uniform(
                3.0,
                6.5
            )


        # ----------------------------------
        # Feature calculations
        # ----------------------------------

        safe_window = max(
            time_window,
            1
        )

        modification_rate = (
            modification_count /
            safe_window
        )

        rename_rate = (
            rename_count /
            safe_window
        )

        total_file_activity = (
            modification_count +
            rename_count
        )

        file_activity_rate = (
            total_file_activity /
            safe_window
        )

        modification_rename_ratio = (
            modification_count /
            (rename_count + 1)
        )

        entropy_risk = (
            entropy / 8.0
        )

        high_entropy = int(
            entropy >= 7.0
        )

        high_file_activity = int(
            total_file_activity >= 10
        )

        behavior_score = (
            entropy_risk +
            file_activity_rate +
            suspicious_extension
        )

        system_load = (
            cpu_usage * 0.7 +
            memory_usage * 0.3
        )

        log_file_size = np.log1p(
            file_size
        )


        rows.append({

            "Session_ID":
                session_id,

            "Scenario":
                scenario,

            "Entropy":
                round(entropy, 4),

            "Rename_Count":
                rename_count,

            "Modification_Count":
                modification_count,

            "CPU_Usage":
                round(cpu_usage, 2),

            "Memory_Usage":
                round(memory_usage, 2),

            "File_Size":
                file_size,

            "Suspicious_Extension":
                suspicious_extension,

            "Time_Window":
                time_window,

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
                total_file_activity,

            "File_Activity_Rate":
                round(
                    file_activity_rate,
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
                ),

            "Label":
                "Normal"
        })

    return rows


# ==========================================
# RANSOMWARE GENERATOR
# ==========================================

def generate_ransomware_activity(
    session_id,
    scenario
):
    """
    Generate synthetic ransomware-like
    behavioral records.

    No actual encryption or destructive
    activity is performed.
    """

    rows = []

    number_of_rows = random.randint(
        MIN_ROWS_PER_SESSION,
        MAX_ROWS_PER_SESSION
    )

    for _ in range(number_of_rows):

        time_window = random.choice([
            5,
            10,
            15,
            20
        ])


        # ----------------------------------
        # Base ransomware behavior
        # ----------------------------------

        entropy = random.uniform(
            6.0,
            8.0
        )

        rename_count = random.randint(
            8,
            50
        )

        modification_count = random.randint(
            15,
            80
        )

        cpu_usage = random.uniform(
            20,
            90
        )

        memory_usage = random.uniform(
            25,
            80
        )

        file_size = random.randint(
            5_000,
            50_000_000
        )

        suspicious_extension = random.choice([
            0,
            1
        ])


        # ----------------------------------
        # Ransomware scenario variations
        # ----------------------------------

        if scenario == "rapid_modification":

            modification_count = random.randint(
                40,
                100
            )

            rename_count = random.randint(
                10,
                50
            )

            entropy = random.uniform(
                6.2,
                8.0
            )


        elif scenario == "mass_rename":

            rename_count = random.randint(
                40,
                100
            )

            modification_count = random.randint(
                20,
                70
            )

            entropy = random.uniform(
                5.8,
                7.8
            )


        elif scenario == "high_entropy":

            entropy = random.uniform(
                7.0,
                8.0
            )

            modification_count = random.randint(
                20,
                70
            )

            rename_count = random.randint(
                5,
                40
            )


        elif scenario == "low_extension":

            # Important hard case:
            # ransomware-like activity without
            # a suspicious filename extension.

            suspicious_extension = 0

            entropy = random.uniform(
                6.0,
                7.8
            )

            modification_count = random.randint(
                30,
                90
            )

            rename_count = random.randint(
                10,
                60
            )


        elif scenario == "slow_activity":

            time_window = random.choice([
                30,
                60
            ])

            entropy = random.uniform(
                5.8,
                7.5
            )

            modification_count = random.randint(
                10,
                35
            )

            rename_count = random.randint(
                5,
                25
            )


        # ----------------------------------
        # Feature calculations
        # ----------------------------------

        safe_window = max(
            time_window,
            1
        )

        modification_rate = (
            modification_count /
            safe_window
        )

        rename_rate = (
            rename_count /
            safe_window
        )

        total_file_activity = (
            modification_count +
            rename_count
        )

        file_activity_rate = (
            total_file_activity /
            safe_window
        )

        modification_rename_ratio = (
            modification_count /
            (rename_count + 1)
        )

        entropy_risk = (
            entropy / 8.0
        )

        high_entropy = int(
            entropy >= 7.0
        )

        high_file_activity = int(
            total_file_activity >= 10
        )

        behavior_score = (
            entropy_risk +
            file_activity_rate +
            suspicious_extension
        )

        system_load = (
            cpu_usage * 0.7 +
            memory_usage * 0.3
        )

        log_file_size = np.log1p(
            file_size
        )


        rows.append({

            "Session_ID":
                session_id,

            "Scenario":
                scenario,

            "Entropy":
                round(entropy, 4),

            "Rename_Count":
                rename_count,

            "Modification_Count":
                modification_count,

            "CPU_Usage":
                round(cpu_usage, 2),

            "Memory_Usage":
                round(memory_usage, 2),

            "File_Size":
                file_size,

            "Suspicious_Extension":
                suspicious_extension,

            "Time_Window":
                time_window,

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
                total_file_activity,

            "File_Activity_Rate":
                round(
                    file_activity_rate,
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
                ),

            "Label":
                "Ransomware"
        })

    return rows


# ==========================================
# GENERATE DATASET
# ==========================================

normal_scenarios = [
    "ordinary",
    "backup",
    "archive",
    "bulk_copy",
    "photo_processing",
    "software_update",
    "bulk_rename"
]

ransomware_scenarios = [
    "rapid_modification",
    "mass_rename",
    "high_entropy",
    "low_extension",
    "slow_activity"
]


all_rows = []


# ==========================================
# NORMAL SESSIONS
# ==========================================

for session_number in range(
    1,
    NORMAL_SESSIONS + 1
):

    session_id = (
        f"normal_{session_number:03d}"
    )

    scenario = random.choice(
        normal_scenarios
    )

    rows = generate_normal_activity(
        session_id,
        scenario
    )

    all_rows.extend(rows)


# ==========================================
# RANSOMWARE SESSIONS
# ==========================================

for session_number in range(
    1,
    RANSOMWARE_SESSIONS + 1
):

    session_id = (
        f"ransomware_{session_number:03d}"
    )

    scenario = random.choice(
        ransomware_scenarios
    )

    rows = generate_ransomware_activity(
        session_id,
        scenario
    )

    all_rows.extend(rows)


# ==========================================
# DATAFRAME
# ==========================================

df = pd.DataFrame(
    all_rows
)


# ==========================================
# SHUFFLE
# ==========================================

df = df.sample(
    frac=1,
    random_state=RANDOM_STATE
).reset_index(
    drop=True
)


# ==========================================
# SAVE
# ==========================================

df.to_csv(
    OUTPUT_FILE,
    index=False
)


# ==========================================
# SUMMARY
# ==========================================

print("\n==========================================")
print("SESSION DATASET CREATED")
print("==========================================")

print(
    "Total rows:",
    len(df)
)

print(
    "Unique sessions:",
    df["Session_ID"].nunique()
)

print("\nClass distribution:")

print(
    df["Label"].value_counts()
)

print("\nScenario distribution:")

print(
    df.groupby(
        ["Label", "Scenario"]
    ).size()
)


print("\nOutput file:")
print(OUTPUT_FILE)