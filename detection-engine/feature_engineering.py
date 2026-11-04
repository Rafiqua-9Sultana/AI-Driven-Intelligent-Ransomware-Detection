import pandas as pd
import numpy as np


INPUT_FILE = "dataset_clean.csv"
OUTPUT_FILE = "dataset_features.csv"


print("\n==========================================")
print("BEHAVIORAL FEATURE ENGINEERING")
print("==========================================\n")


# ==========================================
# LOAD DATA
# ==========================================

df = pd.read_csv(INPUT_FILE)

print("Input rows:", len(df))


# ==========================================
# BASIC BEHAVIORAL RATES
# ==========================================

# Protect against division by zero
time_window = df["Time_Window"].replace(0, 1)


df["Modification_Rate"] = (
    df["Modification_Count"] /
    time_window
)


df["Rename_Rate"] = (
    df["Rename_Count"] /
    time_window
)


# ==========================================
# COMBINED FILE ACTIVITY
# ==========================================

df["Total_File_Activity"] = (
    df["Modification_Count"] +
    df["Rename_Count"]
)


df["File_Activity_Rate"] = (
    df["Total_File_Activity"] /
    time_window
)


# ==========================================
# MODIFICATION / RENAME RATIO
# ==========================================

df["Modification_Rename_Ratio"] = (
    df["Modification_Count"] /
    (df["Rename_Count"] + 1)
)


# ==========================================
# ENTROPY RISK
# ==========================================

# Distance from high entropy.
# Maximum byte entropy is approximately 8.

df["Entropy_Risk"] = (
    df["Entropy"] / 8.0
)


# ==========================================
# HIGH ENTROPY INDICATOR
# ==========================================

df["High_Entropy"] = (
    (df["Entropy"] >= 7.0)
    .astype(int)
)


# ==========================================
# HIGH ACTIVITY INDICATOR
# ==========================================

df["High_File_Activity"] = (
    (df["Total_File_Activity"] >= 10)
    .astype(int)
)


# ==========================================
# COMBINED BEHAVIOR SCORE
# ==========================================

df["Behavior_Score"] = (

    df["Entropy_Risk"] +

    df["File_Activity_Rate"] +

    df["Suspicious_Extension"]

)


# ==========================================
# CPU / MEMORY COMBINED LOAD
# ==========================================

df["System_Load"] = (
    df["CPU_Usage"] * 0.7 +
    df["Memory_Usage"] * 0.3
)


# ==========================================
# FILE SIZE LOG TRANSFORMATION
# ==========================================

df["Log_File_Size"] = np.log1p(
    df["File_Size"]
)


# ==========================================
# ROUND FLOAT FEATURES
# ==========================================

float_columns = df.select_dtypes(
    include=["float64"]
).columns

df[float_columns] = df[
    float_columns
].round(4)


# ==========================================
# DISPLAY NEW FEATURES
# ==========================================

print("\nNew behavioral features:")

new_features = [
    "Modification_Rate",
    "Rename_Rate",
    "Total_File_Activity",
    "File_Activity_Rate",
    "Modification_Rename_Ratio",
    "Entropy_Risk",
    "High_Entropy",
    "High_File_Activity",
    "Behavior_Score",
    "System_Load",
    "Log_File_Size"
]

for feature in new_features:
    print(" -", feature)


# ==========================================
# CHECK FOR NaN / INFINITY
# ==========================================

df = df.replace(
    [np.inf, -np.inf],
    np.nan
)


before = len(df)

df = df.dropna().reset_index(
    drop=True
)

removed = before - len(df)

print(
    f"\nRows removed due to invalid "
    f"values: {removed}"
)


# ==========================================
# SAVE
# ==========================================

df.to_csv(
    OUTPUT_FILE,
    index=False
)


print("\n==========================================")
print("FEATURE ENGINEERING COMPLETE")
print("==========================================")

print("Final rows:", len(df))
print("Output:", OUTPUT_FILE)

print("\nDataset shape:")
print(df.shape)

print("\nLabel distribution:")
print(df["Label"].value_counts())

print("\nFeature preview:")
print(
    df[
        [
            "Entropy",
            "Rename_Count",
            "Modification_Count",
            "Modification_Rate",
            "Rename_Rate",
            "Total_File_Activity",
            "File_Activity_Rate",
            "Entropy_Risk",
            "High_Entropy",
            "Behavior_Score",
            "Label"
        ]
    ].head()
)