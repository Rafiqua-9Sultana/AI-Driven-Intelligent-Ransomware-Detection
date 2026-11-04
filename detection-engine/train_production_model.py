import pandas as pd
import joblib

from sklearn.ensemble import RandomForestClassifier


# ==========================================
# CONFIGURATION
# ==========================================

DATASET = "session_dataset.csv"

MODEL_OUTPUT = "ransomware_production_model.pkl"


# ==========================================
# FEATURES
# ==========================================

FEATURES = [

    "Entropy",
    "Rename_Count",
    "Modification_Count",
    "CPU_Usage",
    "Memory_Usage",
    "File_Size",
    "Suspicious_Extension",
    "Time_Window"
]


# ==========================================
# LOAD DATA
# ==========================================

df = pd.read_csv(
    DATASET
)


print("\n==========================================")
print("PRODUCTION MODEL TRAINING")
print("==========================================")


print(
    "Dataset rows:",
    len(df)
)


print(
    "Sessions:",
    df["Session_ID"].nunique()
)


# ==========================================
# TRAINING DATA
# ==========================================

X = df[
    FEATURES
]


y = (
    df["Label"]
    == "Ransomware"
).astype(int)


# ==========================================
# TRAIN MODEL
# ==========================================

model = RandomForestClassifier(

    n_estimators=300,

    class_weight="balanced",

    random_state=42,

    n_jobs=-1
)


model.fit(
    X,
    y
)


# ==========================================
# SAVE MODEL
# ==========================================

joblib.dump(
    model,
    MODEL_OUTPUT
)


print("\nModel saved:")

print(
    MODEL_OUTPUT
)


print("\nFeatures used:")

for feature in FEATURES:

    print(
        "-",
        feature
    )


print("\n==========================================")
print("PRODUCTION MODEL READY")
print("==========================================")