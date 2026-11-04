import joblib
import pandas as pd
import os


MODEL_FILE = "ransomware_model.pkl"


# Load the trained model
if not os.path.exists(MODEL_FILE):
    raise FileNotFoundError(
        f"Model file '{MODEL_FILE}' was not found."
    )

model = joblib.load(MODEL_FILE)


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


def predict_ransomware(
    entropy,
    rename_count,
    modification_count,
    cpu_usage,
    memory_usage,
    file_size,
    suspicious_extension,
    time_window
):
    """
    Use the trained ML model to classify file activity.
    """

    data = pd.DataFrame([[
        entropy,
        rename_count,
        modification_count,
        cpu_usage,
        memory_usage,
        file_size,
        suspicious_extension,
        time_window
    ]], columns=FEATURES)

    prediction = model.predict(data)[0]

    # Get probability if supported by the model
    probabilities = model.predict_proba(data)[0]

    classes = model.classes_

    probability_dict = {
        str(classes[i]): round(float(probabilities[i]), 4)
        for i in range(len(classes))
    }

    return prediction, probability_dict