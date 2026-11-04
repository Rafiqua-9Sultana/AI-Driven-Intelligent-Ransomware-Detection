import pandas as pd
from pathlib import Path


# ==========================================
# CONFIGURATION
# ==========================================

INPUT_FILE = "dataset.csv"
OUTPUT_FILE = "dataset_clean.csv"


# ==========================================
# LOAD DATASET
# ==========================================

print("\n========================================")
print("DATASET CLEANING")
print("========================================\n")

if not Path(INPUT_FILE).exists():

    print(f"ERROR: {INPUT_FILE} not found.")
    raise SystemExit(1)


df = pd.read_csv(INPUT_FILE)

print(f"Original rows: {len(df)}")
print(f"Original columns: {len(df.columns)}")


# ==========================================
# REMOVE EXACT DUPLICATES
# ==========================================

duplicate_count = df.duplicated().sum()

print(f"\nExact duplicates found: {duplicate_count}")

df = df.drop_duplicates().reset_index(drop=True)

print(f"Rows after duplicate removal: {len(df)}")


# ==========================================
# REMOVE INVALID LABELS
# ==========================================

valid_labels = [
    "Normal",
    "Ransomware"
]

before_labels = len(df)

df = df[
    df["Label"].isin(valid_labels)
].copy()

removed_labels = (
    before_labels - len(df)
)

print(
    f"\nInvalid-label rows removed: "
    f"{removed_labels}"
)


# ==========================================
# CHECK MISSING VALUES
# ==========================================

missing_values = df.isnull().sum()

total_missing = missing_values.sum()

print(
    f"\nTotal missing values: "
    f"{total_missing}"
)


# ==========================================
# REMOVE ROWS WITH MISSING VALUES
# ==========================================

if total_missing > 0:

    print(
        "Removing rows containing "
        "missing values..."
    )

    df = df.dropna().reset_index(
        drop=True
    )


# ==========================================
# CHECK NUMERIC FEATURES
# ==========================================

numeric_columns = [
    "Entropy",
    "Rename_Count",
    "Modification_Count",
    "CPU_Usage",
    "Memory_Usage",
    "File_Size",
    "Suspicious_Extension",
    "Time_Window"
]

print("\nChecking numeric features...")

for column in numeric_columns:

    df[column] = pd.to_numeric(
        df[column],
        errors="coerce"
    )


# ==========================================
# REMOVE ROWS THAT BECAME INVALID
# ==========================================

before_numeric = len(df)

df = df.dropna(
    subset=numeric_columns
).reset_index(drop=True)

removed_numeric = (
    before_numeric - len(df)
)

print(
    f"Invalid numeric rows removed: "
    f"{removed_numeric}"
)


# ==========================================
# VALIDATE FEATURE RANGES
# ==========================================

print("\nChecking feature ranges...")


# Entropy should normally be between 0 and 8
invalid_entropy = (
    (df["Entropy"] < 0) |
    (df["Entropy"] > 8)
)

print(
    "Invalid entropy values:",
    invalid_entropy.sum()
)


# CPU should be between 0 and 100
invalid_cpu = (
    (df["CPU_Usage"] < 0) |
    (df["CPU_Usage"] > 100)
)

print(
    "Invalid CPU values:",
    invalid_cpu.sum()
)


# Memory should be between 0 and 100
invalid_memory = (
    (df["Memory_Usage"] < 0) |
    (df["Memory_Usage"] > 100)
)

print(
    "Invalid memory values:",
    invalid_memory.sum()
)


# Suspicious extension should be 0 or 1
invalid_extension = ~df[
    "Suspicious_Extension"
].isin([0, 1])

print(
    "Invalid suspicious-extension values:",
    invalid_extension.sum()
)


# ==========================================
# REMOVE INVALID RANGE ROWS
# ==========================================

valid_rows = (

    (df["Entropy"] >= 0) &
    (df["Entropy"] <= 8) &

    (df["CPU_Usage"] >= 0) &
    (df["CPU_Usage"] <= 100) &

    (df["Memory_Usage"] >= 0) &
    (df["Memory_Usage"] <= 100) &

    (df["Suspicious_Extension"].isin([0, 1]))
)

removed_range = (
    len(df) - valid_rows.sum()
)

df = df[valid_rows].reset_index(
    drop=True
)

print(
    f"Invalid-range rows removed: "
    f"{removed_range}"
)


# ==========================================
# CLASS BALANCE
# ==========================================

print("\n========================================")
print("CLASS DISTRIBUTION")
print("========================================")

class_counts = df["Label"].value_counts()

print(class_counts)

print("\nPercentages:")

class_percentages = (
    df["Label"]
    .value_counts(normalize=True)
    .mul(100)
    .round(2)
)

print(class_percentages)


# ==========================================
# FINAL DUPLICATE CHECK
# ==========================================

final_duplicates = df.duplicated().sum()

print(
    f"\nFinal duplicate count: "
    f"{final_duplicates}"
)


# ==========================================
# SAVE CLEAN DATASET
# ==========================================

df.to_csv(
    OUTPUT_FILE,
    index=False
)

print("\n========================================")
print("CLEANING COMPLETE")
print("========================================")

print(
    f"Final rows: {len(df)}"
)

print(
    f"Output file: {OUTPUT_FILE}"
)

print("\nDataset preview:")

print(
    df.head()
)