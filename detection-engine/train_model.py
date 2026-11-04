import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix


# ============================================================
# CONFIGURATION
# ============================================================

DATASET_FILE = "dataset.csv"
MODEL_FILE = "ransomware_model.pkl"


# ============================================================
# LOAD DATASET
# ============================================================

print("=" * 60)
print("RANSOMWARE DETECTION - ML TRAINING")
print("=" * 60)

print("\nLoading dataset...")

df = pd.read_csv(DATASET_FILE)

print(f"Dataset loaded successfully.")
print(f"Total records: {len(df)}")

print("\nClass distribution:")
print(df["Label"].value_counts())


# ============================================================
# SELECT FEATURES
# ============================================================

features = [
    "Entropy",
    "Rename_Count",
    "Modification_Count",
    "CPU_Usage",
    "Memory_Usage",
    "File_Size",
    "Suspicious_Extension",
    "Time_Window"
]

X = df[features]
y = df["Label"]


# ============================================================
# SPLIT DATA
# ============================================================

print("\nSplitting dataset...")

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

print(f"Training samples: {len(X_train)}")
print(f"Testing samples : {len(X_test)}")


# ============================================================
# CREATE MODEL
# ============================================================

print("\nTraining Random Forest model...")

model = RandomForestClassifier(
    n_estimators=100,
    random_state=42,
    class_weight="balanced"
)

model.fit(X_train, y_train)


# ============================================================
# PREDICTION
# ============================================================

print("\nTesting model...")

y_pred = model.predict(X_test)


# ============================================================
# ACCURACY
# ============================================================

accuracy = accuracy_score(y_test, y_pred)

print("\n" + "=" * 60)
print("MODEL PERFORMANCE")
print("=" * 60)

print(f"\nAccuracy: {accuracy * 100:.2f}%")


# ============================================================
# CLASSIFICATION REPORT
# ============================================================

print("\nClassification Report:")
print(classification_report(y_test, y_pred))


# ============================================================
# CONFUSION MATRIX
# ============================================================

print("Confusion Matrix:")
print(confusion_matrix(y_test, y_pred))


# ============================================================
# FEATURE IMPORTANCE
# ============================================================

print("\nFeature Importance:")

importance = model.feature_importances_

feature_importance = pd.DataFrame({
    "Feature": features,
    "Importance": importance
})

feature_importance = feature_importance.sort_values(
    by="Importance",
    ascending=False
)

print(feature_importance.to_string(index=False))


# ============================================================
# SAVE MODEL
# ============================================================

joblib.dump(model, MODEL_FILE)

print("\n" + "=" * 60)
print("MODEL SAVED SUCCESSFULLY")
print("=" * 60)

print(f"\nModel file: {MODEL_FILE}")
print("\nML training completed.")