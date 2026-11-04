import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
    classification_report
)


# ==========================================
# CONFIGURATION
# ==========================================

DATASET = "session_dataset.csv"

RANDOM_STATE = 42

TEST_SESSION_PERCENTAGE = 0.20


# ==========================================
# LOAD DATA
# ==========================================

df = pd.read_csv(DATASET)


print("\n==========================================")
print("SESSION-BASED MODEL EVALUATION")
print("==========================================")

print(
    "Total rows:",
    len(df)
)

print(
    "Total sessions:",
    df["Session_ID"].nunique()
)


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
# CREATE SESSION TABLE
# ==========================================

session_info = (
    df[
        [
            "Session_ID",
            "Label"
        ]
    ]
    .drop_duplicates()
    .reset_index(drop=True)
)


print("\nSession distribution:")

print(
    session_info["Label"].value_counts()
)


# ==========================================
# STRATIFIED SESSION SPLIT
# ==========================================

normal_sessions = session_info.loc[
    session_info["Label"] == "Normal",
    "Session_ID"
].tolist()


ransomware_sessions = session_info.loc[
    session_info["Label"] == "Ransomware",
    "Session_ID"
].tolist()


# Shuffle deterministically

import random

random.seed(
    RANDOM_STATE
)


random.shuffle(
    normal_sessions
)

random.shuffle(
    ransomware_sessions
)


# Number of test sessions

normal_test_count = max(
    1,
    round(
        len(normal_sessions)
        * TEST_SESSION_PERCENTAGE
    )
)


ransomware_test_count = max(
    1,
    round(
        len(ransomware_sessions)
        * TEST_SESSION_PERCENTAGE
    )
)


# Test sessions

test_normal_sessions = normal_sessions[
    :normal_test_count
]

test_ransomware_sessions = ransomware_sessions[
    :ransomware_test_count
]


test_sessions = set(
    test_normal_sessions +
    test_ransomware_sessions
)


# Training sessions

train_sessions = set(
    session_info["Session_ID"]
) - test_sessions


# ==========================================
# LEAKAGE CHECK
# ==========================================

overlap = (
    train_sessions
    .intersection(test_sessions)
)


print("\n==========================================")
print("SESSION SPLIT")
print("==========================================")

print(
    "Training sessions:",
    len(train_sessions)
)

print(
    "Testing sessions:",
    len(test_sessions)
)

print(
    "Session overlap:",
    len(overlap)
)


if len(overlap) != 0:

    raise RuntimeError(
        "DATA LEAKAGE DETECTED!"
    )


print(
    "✓ No session overlap detected."
)


# ==========================================
# ROW SPLIT
# ==========================================

train_df = df[
    df["Session_ID"].isin(
        train_sessions
    )
].copy()


test_df = df[
    df["Session_ID"].isin(
        test_sessions
    )
].copy()


print("\nTraining rows:")

print(
    len(train_df)
)


print("Testing rows:")

print(
    len(test_df)
)


# ==========================================
# LABEL DISTRIBUTION
# ==========================================

print("\nTraining label distribution:")

print(
    train_df["Label"].value_counts()
)


print("\nTesting label distribution:")

print(
    test_df["Label"].value_counts()
)


# ==========================================
# FEATURES / TARGET
# ==========================================

X_train = train_df[
    FEATURES
]

X_test = test_df[
    FEATURES
]


y_train = (
    train_df["Label"]
    == "Ransomware"
).astype(int)


y_test = (
    test_df["Label"]
    == "Ransomware"
).astype(int)


# ==========================================
# TRAIN MODEL
# ==========================================

print("\n==========================================")
print("TRAINING RANDOM FOREST")
print("==========================================")


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


# ==========================================
# PREDICTION
# ==========================================

predictions = model.predict(
    X_test
)


probabilities = model.predict_proba(
    X_test
)[:, 1]


# ==========================================
# METRICS
# ==========================================

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


# ==========================================
# RESULTS
# ==========================================

print("\n==========================================")
print("UNSEEN SESSION RESULTS")
print("==========================================")


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


# ==========================================
# CONFUSION MATRIX
# ==========================================

cm = confusion_matrix(
    y_test,
    predictions
)


print("\n==========================================")
print("CONFUSION MATRIX")
print("==========================================")


print(cm)


# ==========================================
# CLASSIFICATION REPORT
# ==========================================

print("\n==========================================")
print("CLASSIFICATION REPORT")
print("==========================================")


print(
    classification_report(
        y_test,
        predictions,

        target_names=[
            "Normal",
            "Ransomware"
        ]
    )
)


# ==========================================
# FEATURE IMPORTANCE
# ==========================================

importance = pd.DataFrame({

    "Feature":
        FEATURES,

    "Importance":
        model.feature_importances_

})


importance = importance.sort_values(
    by="Importance",
    ascending=False
)


print("\n==========================================")
print("FEATURE IMPORTANCE")
print("==========================================")


print(
    importance.to_string(
        index=False
    )
)


# ==========================================
# SAVE RESULTS
# ==========================================

results = pd.DataFrame([{

    "Accuracy":
        accuracy,

    "Precision":
        precision,

    "Recall":
        recall,

    "F1":
        f1,

    "ROC_AUC":
        roc_auc,

    "Training_Sessions":
        len(train_sessions),

    "Testing_Sessions":
        len(test_sessions),

    "Training_Rows":
        len(train_df),

    "Testing_Rows":
        len(test_df)

}])


results.to_csv(
    "session_evaluation_results.csv",
    index=False
)


importance.to_csv(
    "session_feature_importance.csv",
    index=False
)


# ==========================================
# SAVE TEST PREDICTIONS
# ==========================================

test_output = test_df[
    [
        "Session_ID",
        "Scenario",
        "Label"
    ]
].copy()


test_output["Actual"] = (
    y_test
    .map({
        0: "Normal",
        1: "Ransomware"
    })
    .values
)


test_output["Predicted"] = (
    predictions
    .astype(int)
)


test_output["Predicted"] = (
    test_output["Predicted"]
    .map({
        0: "Normal",
        1: "Ransomware"
    })
)


test_output["Ransomware_Probability"] = (
    probabilities
)


test_output.to_csv(
    "session_test_predictions.csv",
    index=False
)


print("\n==========================================")
print("FILES SAVED")
print("==========================================")

print(
    "session_evaluation_results.csv"
)

print(
    "session_feature_importance.csv"
)

print(
    "session_test_predictions.csv"
)

print("\nEvaluation complete.")