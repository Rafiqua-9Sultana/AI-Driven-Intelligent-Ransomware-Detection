# 🛡️ AI-Driven Intelligent Ransomware Detection System

<p align="center">
  <strong>AI-Based Behavioural Analysis for Ransomware Detection</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11-blue?logo=python" />
  <img src="https://img.shields.io/badge/Machine%20Learning-Random%20Forest-green" />
  <img src="https://img.shields.io/badge/Backend-FastAPI-009688?logo=fastapi" />
  <img src="https://img.shields.io/badge/Frontend-React-61DAFB?logo=react" />
  <img src="https://img.shields.io/badge/Database-SQLite-lightgrey?logo=sqlite" />
</p>

## 📌 About the Project

The **AI-Driven Intelligent Ransomware Detection System** is a machine-learning-based security application designed to identify suspicious file-system activities that resemble ransomware behaviour.

The system monitors selected file activities, extracts behavioural and system-level features, and uses a trained Random Forest classifier to estimate the probability of ransomware activity.

It integrates a Python monitoring engine, FastAPI backend, SQLite database, and React dashboard to provide detection results, historical records, statistics, and alerts.

## 🎯 Objectives

- Monitor selected file-system activities.
- Extract eight behavioural and system-usage features.
- Detect ransomware-like behaviour using a Random Forest classifier.
- Apply a probability threshold of 0.60 for classification.
- Store detection events using FastAPI and SQLite.
- Display detection results through an interactive dashboard.
- Evaluate model performance using standard classification metrics.

## ⚙️ Key Features

- **Real-Time File Monitoring:** Observes file creation, modification, and rename events in the configured demo folder.
- **Behavioural Feature Extraction:** Extracts eight numerical features for classification.
- **Machine Learning Detection:** Uses a trained Random Forest model containing 300 decision trees.
- **Probability-Based Classification:** Classifies events using a ransomware probability threshold of 0.60.
- **Detection History:** Stores and retrieves previous detection records.
- **Analytics Dashboard:** Displays detection statistics, probabilities, and event distribution.
- **Alert Notifications:** Supports browser notifications and audio alerts for ransomware-classified events.
- **JWT Authentication:** Protects dashboard endpoints that require authentication.

## 🧠 Machine Learning Model

The system uses a trained **Random Forest Classifier** to distinguish normal file activity from ransomware-like behaviour.

### Eight Input Features

| No. | Feature | Description |
|---|---|---|
| 1 | Entropy | Measures randomness in file content |
| 2 | Rename_Count | Number of observed rename events |
| 3 | Modification_Count | Number of file modifications |
| 4 | CPU_Usage | CPU utilization percentage |
| 5 | Memory_Usage | Memory utilization percentage |
| 6 | File_Size | Numerical file-size measurement |
| 7 | Suspicious_Extension | Indicates configured suspicious extensions |
| 8 | Time_Window | Configured monitoring interval |

### Classification Threshold

The production model uses a threshold of **0.60**.

- Ransomware probability ≥ 0.60 → Ransomware
- Ransomware probability < 0.60 → Normal

## 🏗️ System Architecture

The system consists of four major components:

1. **Monitoring Engine:** Uses Python Watchdog to monitor file-system activities and extract behavioural features.
2. **Machine Learning Model:** Processes the extracted features using the trained Random Forest classifier.
3. **Backend and Database:** Uses FastAPI to receive detection records and SQLite to store them.
4. **Frontend Dashboard:** Uses React and Vite to display detection results, history, analytics, and notifications.

### Detection Workflow

```text
File System Activity
        |
        v
Watchdog Monitoring
        |
        v
Behavioural Feature Extraction
        |
        v
Random Forest Classifier
        |
        v
Probability Calculation
        |
        v
Threshold Decision (0.60)
        |
        v
FastAPI Backend
        |
        v
SQLite Database
        |
        v
React Dashboard
        |
        v
Detection Results & Alerts
```

## 🛠️ Technologies Used

| Category | Technologies |
|---|---|
| Programming Language | Python 3.11 |
| Machine Learning | Scikit-learn, Random Forest |
| File Monitoring | Watchdog |
| System Monitoring | psutil |
| Model Storage | Joblib |
| Backend | FastAPI, Uvicorn |
| Database | SQLite |
| Frontend | React, Vite, JavaScript |
| API Communication | Axios, REST API |
| Authentication | JWT |
| Development Tools | VS Code, Windows |

## 📊 Model Evaluation Results

The model was evaluated using the available threshold evaluation dataset.

### Performance at 0.60 Threshold

| Evaluation Metric | Result |
|---|---:|
| Accuracy | 97.01% |
| Precision | 96.64% |
| Recall | 96.00% |
| F1-Score | 96.32% |
| False Positive Rate | 2.29% |
| False Negative Rate | 4.00% |

### Confusion Matrix

| Actual / Predicted | Normal | Ransomware |
|---|---:|---:|
| Actual Normal | 213 | 5 |
| Actual Ransomware | 6 | 144 |

*Note: These results represent the available model evaluation data and do not guarantee equivalent performance on unseen systems or real-world ransomware.*

## 📁 Project Modules

- File Monitoring Module
- Behavioural Feature Extraction Module
- Machine Learning Classification Module
- Threshold-Based Detection Module
- Backend API Module
- Database Management Module
- Dashboard and Analytics Module
- Notification and Alert Module

## 🔒 Safety Considerations

The project uses a controlled simulator to generate ransomware-like file activity for testing.

- Monitoring is restricted to the configured `demo_folder`.
- The simulator does not implement real file encryption or deletion.
- Automatic quarantine, process termination, and file recovery are not currently implemented.
- Testing should be performed using disposable test files and folders.

## 🚀 Future Enhancements

- Expand monitoring to additional directories and endpoint activities.
- Evaluate the model using larger and independent datasets.
- Improve detection of previously unseen ransomware variants.
- Introduce safe quarantine and file recovery mechanisms.
- Integrate additional network-level behavioural indicators.
- Improve deployment security and access control.
- Optimize detection performance and response time.

## 👩‍💻 Developed With

**AI-Driven Intelligent Ransomware Detection System**

A machine-learning-based approach to identifying suspicious file activity through behavioural analysis and intelligent classification.

---

<p align="center">
  <strong>Building Intelligent Security Through Machine Learning 🛡️</strong>
</p>