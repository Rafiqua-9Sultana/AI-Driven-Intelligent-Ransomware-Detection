import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix
)


# ==========================================
# CONFIGURATION
# ==========================================

DATASET = "dataset_augmented.csv"

RANDOM_STATE = 42


# ==========================================
# LOAD DATA
# ==========================================

df = pd.read_csv(DATASET)


# ==========================================
# ALL FEATURES
# ==========================================

ALL_FEATURES = [

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


# ==========================================
# EXPERIMENTS
# ==========================================

experiments = {

    "All Features":

        ALL_FEATURES,


    "Without Suspicious Extension":

        [
            feature
            for feature in ALL_FEATURES
            if feature != "Suspicious_Extension"
        ],


    "Behavioral Only":

        [
            feature
            for feature in ALL_FEATURES

            if feature not in [

                "Suspicious_Extension",

                "Entropy_Risk",

                "High_Entropy",

                "Behavior_Score"
            ]
        ]
}


# ==========================================
# TARGET
# ==========================================

y = (
    df["Label"] == "Ransomware"
).astype(int)


# ==========================================
# RESULTS
# ==========================================

results = []


# ==========================================
# RUN EXPERIMENTS
# ==========================================

for experiment_name, features in experiments.items():

    print("\n")
    print("==========================================")
    print(experiment_name)
    print("==========================================")

    print(
        "Number of features:",
        len(features)
    )

    X = df[features]


    # --------------------------------------
    # Train/test split
    # --------------------------------------

    X_train, X_test, y_train, y_test = train_test_split(

        X,
        y,

        test_size=0.20,

        random_state=RANDOM_STATE,

        stratify=y
    )


    # --------------------------------------
    # Model
    # --------------------------------------

    model = RandomForestClassifier(

        n_estimators=300,

        class_weight="balanced",

        random_state=RANDOM_STATE,

        n_jobs=-1
    )


    model.fit(
        X_train,
        y_train
    )


    # --------------------------------------
    # Predictions
    # --------------------------------------

    predictions = model.predict(
        X_test
    )

    probabilities = model.predict_proba(
        X_test
    )[:, 1]


    # --------------------------------------
    # Metrics
    # --------------------------------------

    accuracy = accuracy_score(
        y_test,
        predictions
    )

    precision = precision_score(
        y_test,
        predictions
    )

    recall = recall_score(
        y_test,
        predictions
    )

    f1 = f1_score(
        y_test,
        predictions
    )

    roc_auc = roc_auc_score(
        y_test,
        probabilities
    )


    cm = confusion_matrix(
        y_test,
        predictions
    )


    # --------------------------------------
    # Print
    # --------------------------------------

    print(
        f"Accuracy : {accuracy:.4f}"
    )

    print(
        f"Precision: {precision:.4f}"
    )

    print(
        f"Recall   : {recall:.4f}"
    )

    print(
        f"F1       : {f1:.4f}"
    )

    print(
        f"ROC-AUC  : {roc_auc:.4f}"
    )


    print("\nConfusion matrix:")

    print(cm)


    # --------------------------------------
    # Save result
    # --------------------------------------

    results.append({

        "Experiment":
            experiment_name,

        "Features":
            len(features),

        "Accuracy":
            accuracy,

        "Precision":
            precision,

        "Recall":
            recall,

        "F1":
            f1,

        "ROC_AUC":
            roc_auc
    })


# ==========================================
# RESULTS TABLE
# ==========================================

results_df = pd.DataFrame(
    results
)


print("\n")
print("==========================================")
print("ABLATION RESULTS")
print("==========================================")


print(
    results_df.to_string(
        index=False
    )
)


results_df.to_csv(
    "ablation_results.csv",
    index=False
)


print(
    "\nSaved: ablation_results.csv"
)