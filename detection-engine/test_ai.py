from ai_detector import predict_ransomware


# ------------------------------------------------------------
# Test 1: Normal activity
# ------------------------------------------------------------

prediction, probabilities = predict_ransomware(
    entropy=4.5,
    rename_count=0,
    modification_count=2,
    cpu_usage=20,
    memory_usage=50,
    file_size=4096,
    suspicious_extension=0,
    time_window=30
)

print("\nNORMAL TEST")
print("Prediction:", prediction)
print("Probabilities:", probabilities)


# ------------------------------------------------------------
# Test 2: Ransomware-like activity
# ------------------------------------------------------------

prediction, probabilities = predict_ransomware(
    entropy=7.95,
    rename_count=8,
    modification_count=30,
    cpu_usage=70,
    memory_usage=80,
    file_size=4096,
    suspicious_extension=1,
    time_window=15
)

print("\nRANSOMWARE TEST")
print("Prediction:", prediction)
print("Probabilities:", probabilities)