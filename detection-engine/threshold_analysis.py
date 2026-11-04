import random

import pandas as pd

from sklearn.ensemble import RandomForestClassifier

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix
)


# ==========================================
# CONFIGURATION
# ==========================================

DATASET = "session_dataset.csv"

RANDOM_STATE = 42

TEST_PERCENTAGE = 0.20


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


# ==========================================
# SESSION INFORMATION
# ==========================================

session_info = (
    df[
        [
            "Session_ID",
            "Label"
        ]
    ]
    .drop_duplicates()
)


normal_sessions = session_info.loc[
    session_info["Label"] == "Normal",
    "Session_ID"
].tolist()


ransomware_sessions = session_info.loc[
    session_info["Label"] == "Ransomware",
    "Session_ID"
].tolist()


random.seed(
    RANDOM_STATE
)


random.shuffle(
    normal_sessions
)

random.shuffle(
    ransomware_sessions
)


# ==========================================
# SESSION SPLIT
# ==========================================

normal_test_count = round(
    len(normal_sessions)
    * TEST_PERCENTAGE
)

ransomware_test_count = round(
    len(ransomware_sessions)
    * TEST_PERCENTAGE
)


test_sessions = set(

    normal_sessions[
        :normal_test_count
    ]

    +

    ransomware_sessions[
        :ransomware_test_count
    ]
)


train_sessions = (

    set(
        session_info["Session_ID"]
    )

    -

    test_sessions
)


# ==========================================
# LEAKAGE CHECK
# ==========================================

assert not (
    train_sessions &
    test_sessions
)


# ==========================================
# TRAIN / TEST DATA
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
print("TRAINING RAW FEATURE MODEL")
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
# PROBABILITIES
# ==========================================

probabilities = model.predict_proba(
    X_test
)[:, 1]


# ==========================================
# THRESHOLD TESTING
# ==========================================

thresholds = [

    0.10,
    0.20,
    0.30,
    0.40,
    0.50,
    0.60,
    0.70,
    0.80,
    0.90
]


results = []


print("\n==========================================")
print("THRESHOLD ANALYSIS")
print("==========================================\n")


for threshold in thresholds:

    predictions = (
        probabilities >= threshold
    ).astype(int)


    accuracy = accuracy_score(
        y_test,
        predictions
    )


    precision = precision_score(
        y_test,
        predictions,
        zero_division=0
    )


    recall = recall_score(
        y_test,
        predictions,
        zero_division=0
    )


    f1 = f1_score(
        y_test,
        predictions,
        zero_division=0
    )


    cm = confusion_matrix(
        y_test,
        predictions
    )


    tn, fp, fn, tp = cm.ravel()


    # False positive rate
    false_positive_rate = (
        fp /
        (fp + tn)
    )


    # False negative rate
    false_negative_rate = (
        fn /
        (fn + tp)
    )


    print(
        f"Threshold: {threshold:.2f}"
    )

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
        f"FPR      : {false_positive_rate:.4f}"
    )

    print(
        f"FNR      : {false_negative_rate:.4f}"
    )

    print(
        "Confusion matrix:"
    )

    print(cm)

    print(
        "------------------------------------------"
    )


    results.append({

        "Threshold":
            threshold,

        "Accuracy":
            accuracy,

        "Precision":
            precision,

        "Recall":
            recall,

        "F1":
            f1,

        "False_Positive_Rate":
            false_positive_rate,

        "False_Negative_Rate":
            false_negative_rate,

        "TN":
            tn,

        "FP":
            fp,

        "FN":
            fn,

        "TP":
            tp
    })


# ==========================================
# RESULTS TABLE
# ==========================================

results_df = pd.DataFrame(
    results
)


print("\n==========================================")
print("THRESHOLD SUMMARY")
print("==========================================\n")


print(
    results_df.to_string(
        index=False
    )
)


# ==========================================
# BEST F1
# ==========================================

best_f1 = results_df.loc[
    results_df["F1"].idxmax()
]


print("\n==========================================")
print("BEST F1 THRESHOLD")
print("==========================================")


print(
    best_f1.to_string()
)


# ==========================================
# SECURITY-ORIENTED THRESHOLD
# ==========================================

# Select the highest precision threshold
# that still maintains >= 95% recall.

security_candidates = results_df[
    results_df["Recall"] >= 0.95
]


if not security_candidates.empty:

    security_choice = (
        security_candidates
        .sort_values(
            by="Precision",
            ascending=False
        )
        .iloc[0]
    )


    print("\n==========================================")
    print("SECURITY-ORIENTED THRESHOLD")
    print("==========================================")


    print(
        security_choice.to_string()
    )


# ==========================================
# SAVE
# ==========================================

results_df.to_csv(
    "threshold_results.csv",
    index=False
)


print(
    "\nSaved: threshold_results.csv"
)