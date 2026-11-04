import pandas as pd

from sklearn.ensemble import RandomForestClassifier

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix
)

import random


# ==========================================
# CONFIGURATION
# ==========================================

DATASET = "session_dataset.csv"

RANDOM_STATE = 42

TEST_PERCENTAGE = 0.20


# ==========================================
# LOAD DATA
# ==========================================

df = pd.read_csv(DATASET)


# ==========================================
# RAW FEATURES
# ==========================================

RAW_FEATURES = [

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
# BEHAVIORAL FEATURES
# ==========================================

BEHAVIORAL_FEATURES = [

    "Modification_Rate",
    "Rename_Rate",
    "Total_File_Activity",
    "File_Activity_Rate",
    "Modification_Rename_Ratio"
]


# ==========================================
# DERIVED FEATURES
# ==========================================

DERIVED_FEATURES = [

    "Entropy_Risk",
    "High_Entropy",
    "High_File_Activity",
    "Behavior_Score",
    "System_Load",
    "Log_File_Size"
]


# ==========================================
# FEATURE GROUPS
# ==========================================

experiments = {

    "Raw Features":

        RAW_FEATURES,


    "Raw + Behavioral":

        RAW_FEATURES +
        BEHAVIORAL_FEATURES,


    "Raw + Behavioral + Derived":

        RAW_FEATURES +
        BEHAVIORAL_FEATURES +
        DERIVED_FEATURES
}


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


train_df = df[
    df["Session_ID"].isin(
        train_sessions
    )
]


test_df = df[
    df["Session_ID"].isin(
        test_sessions
    )
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
# RESULTS
# ==========================================

results = []


# ==========================================
# EXPERIMENT LOOP
# ==========================================

for name, features in experiments.items():

    print("\n")
    print("==========================================")
    print(name)
    print("==========================================")

    print(
        "Feature count:",
        len(features)
    )


    X_train = train_df[
        features
    ]

    X_test = test_df[
        features
    ]


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


    predictions = model.predict(
        X_test
    )


    probabilities = model.predict_proba(
        X_test
    )[:, 1]


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


    results.append({

        "Experiment":
            name,

        "Feature_Count":
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
# SAVE
# ==========================================

results_df = pd.DataFrame(
    results
)


print("\n")
print("==========================================")
print("RAW VS ENGINEERED RESULTS")
print("==========================================")


print(
    results_df.to_string(
        index=False
    )
)


results_df.to_csv(
    "raw_vs_engineered_results.csv",
    index=False
)


print(
    "\nSaved: raw_vs_engineered_results.csv"
)