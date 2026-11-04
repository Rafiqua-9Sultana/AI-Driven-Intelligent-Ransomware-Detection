import pandas as pd
import numpy as np

from sklearn.ensemble import RandomForestClassifier
from sklearn.inspection import permutation_importance


DATASET = "dataset_augmented.csv"


# ==========================================
# LOAD DATA
# ==========================================

df = pd.read_csv(DATASET)

features = [
    "Entropy",
    "Rename_Count",
    "Modification_Count",
    "CPU_Usage",
    "Memory_Usage",
    "File_Size",
    "Suspicious_Extension",
    "Time_Window",
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


X = df[features]

y = (
    df["Label"] == "Ransomware"
).astype(int)


# ==========================================
# FEATURE STATISTICS
# ==========================================

print("\n==========================================")
print("FEATURE SEPARATION ANALYSIS")
print("==========================================\n")


for feature in features:

    normal = df.loc[
        df["Label"] == "Normal",
        feature
    ]

    ransomware = df.loc[
        df["Label"] == "Ransomware",
        feature
    ]

    print("------------------------------------------")
    print(feature)

    print(
        "Normal:",
        f"mean={normal.mean():.4f}",
        f"median={normal.median():.4f}"
    )

    print(
        "Ransomware:",
        f"mean={ransomware.mean():.4f}",
        f"median={ransomware.median():.4f}"
    )


# ==========================================
# RANDOM FOREST IMPORTANCE
# ==========================================

print("\n==========================================")
print("RANDOM FOREST FEATURE IMPORTANCE")
print("==========================================\n")


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


importance = pd.DataFrame({

    "Feature": features,

    "Importance":
        model.feature_importances_

})


importance = importance.sort_values(
    by="Importance",
    ascending=False
)


print(
    importance.to_string(
        index=False
    )
)


importance.to_csv(
    "feature_importance.csv",
    index=False
)


print(
    "\nSaved: feature_importance.csv"
)