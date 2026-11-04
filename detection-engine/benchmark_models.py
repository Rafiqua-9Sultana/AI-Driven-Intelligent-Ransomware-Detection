import pandas as pd
import numpy as np

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline

from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.ensemble import GradientBoostingClassifier

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

DATASET = "dataset_augmented.csv"

RANDOM_STATE = 42


# ==========================================
# LOAD DATASET
# ==========================================

print("\n==========================================")
print("RANSOMWARE MODEL BENCHMARK")
print("==========================================\n")

df = pd.read_csv(DATASET)

print("Dataset shape:", df.shape)

print("\nClass distribution:")
print(df["Label"].value_counts())


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


X = df[FEATURES]

y = df["Label"]


# ==========================================
# TRAIN / TEST SPLIT
# ==========================================

X_train, X_test, y_train, y_test = train_test_split(

    X,
    y,

    test_size=0.20,

    random_state=RANDOM_STATE,

    stratify=y
)


print("\nTraining samples:", len(X_train))
print("Testing samples:", len(X_test))


# ==========================================
# MODELS
# ==========================================

models = {

    "Logistic Regression":

        Pipeline([
            (
                "scaler",
                StandardScaler()
            ),

            (
                "model",
                LogisticRegression(
                    max_iter=2000,
                    class_weight="balanced",
                    random_state=RANDOM_STATE
                )
            )
        ]),


    "Random Forest":

        RandomForestClassifier(

            n_estimators=300,

            max_depth=None,

            min_samples_split=4,

            class_weight="balanced",

            random_state=RANDOM_STATE,

            n_jobs=-1
        ),


    "Gradient Boosting":

        GradientBoostingClassifier(

            n_estimators=200,

            learning_rate=0.05,

            max_depth=3,

            random_state=RANDOM_STATE
        )
}


# ==========================================
# RESULTS
# ==========================================

results = []


# ==========================================
# TRAIN MODELS
# ==========================================

for model_name, model in models.items():

    print("\n")
    print("==========================================")
    print(model_name)
    print("==========================================")


    # Train

    model.fit(
        X_train,
        y_train
    )


    # Predictions

    predictions = model.predict(
        X_test
    )


    probabilities = model.predict_proba(
        X_test
    )


    # Find Ransomware probability column

    ransomware_index = list(
        model.classes_
    ).index("Ransomware")


    ransomware_probability = (
        probabilities[:, ransomware_index]
    )


    # Metrics

    accuracy = accuracy_score(
        y_test,
        predictions
    )


    precision = precision_score(
        y_test,
        predictions,
        pos_label="Ransomware"
    )


    recall = recall_score(
        y_test,
        predictions,
        pos_label="Ransomware"
    )


    f1 = f1_score(
        y_test,
        predictions,
        pos_label="Ransomware"
    )


    y_test_binary = (
        y_test == "Ransomware"
    ).astype(int)


    roc_auc = roc_auc_score(
        y_test_binary,
        ransomware_probability
    )


    cm = confusion_matrix(
        y_test,
        predictions,
        labels=[
            "Normal",
            "Ransomware"
        ]
    )


    print(
        f"\nAccuracy:  {accuracy:.4f}"
    )

    print(
        f"Precision: {precision:.4f}"
    )

    print(
        f"Recall:    {recall:.4f}"
    )

    print(
        f"F1 Score:  {f1:.4f}"
    )

    print(
        f"ROC-AUC:   {roc_auc:.4f}"
    )


    print("\nConfusion Matrix:")

    print(
        "                 Predicted"
    )

    print(
        "              Normal  Ransomware"
    )

    print(
        f"Actual Normal     {cm[0][0]:4d}      {cm[0][1]:4d}"
    )

    print(
        f"Actual Ransomware {cm[1][0]:4d}      {cm[1][1]:4d}"
    )


    print("\nClassification Report:")

    print(
        classification_report(
            y_test,
            predictions
        )
    )


    results.append({

        "Model":
            model_name,

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


results_df = results_df.sort_values(
    by="F1",
    ascending=False
)


print("\n")
print("==========================================")
print("MODEL COMPARISON")
print("==========================================")


print(
    results_df.to_string(
        index=False
    )
)


# ==========================================
# SAVE RESULTS
# ==========================================

results_df.to_csv(
    "model_benchmark_results.csv",
    index=False
)


print(
    "\nResults saved to:"
    " model_benchmark_results.csv"
)


print("\nBenchmark complete.")