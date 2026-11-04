from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime


# ==========================================
# FASTAPI APPLICATION
# ==========================================

app = FastAPI(
    title="Ransomware Detection API",
    description="AI-powered ransomware detection backend",
    version="1.0.0"
)


# ==========================================
# CORS
# ==========================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ==========================================
# LATEST DETECTION
# ==========================================

latest_detection = {
    "prediction": "Normal",
    "normal_probability": 1.0,
    "ransomware_probability": 0.0,
    "alert": False,
    "file": None,
    "timestamp": None
}


# ==========================================
# ROOT
# ==========================================

@app.get("/")
def root():

    return {
        "message": "Ransomware Detection API is running",
        "status": "online"
    }


# ==========================================
# HEALTH CHECK
# ==========================================

@app.get("/health")
def health():

    return {
        "status": "healthy"
    }


# ==========================================
# GET LATEST DETECTION
# ==========================================

@app.get("/detection/latest")
def get_latest_detection():

    return latest_detection


# ==========================================
# UPDATE DETECTION
# ==========================================

@app.post("/detection/update")
def update_detection(data: dict):

    global latest_detection

    # --------------------------------------
    # Get prediction
    # --------------------------------------

    prediction = data.get(
        "prediction",
        "Normal"
    )


    # --------------------------------------
    # Get probabilities
    # --------------------------------------

    probabilities = data.get(
        "probabilities",
        {}
    )

    normal_probability = float(
        probabilities.get(
            "Normal",
            0.0
        )
    )

    ransomware_probability = float(
        probabilities.get(
            "Ransomware",
            0.0
        )
    )


    # --------------------------------------
    # Get file
    # --------------------------------------

    suspicious_file = data.get(
        "suspicious_file",
        data.get("file")
    )


    # --------------------------------------
    # Determine alert
    # --------------------------------------

    alert = (
        prediction.lower()
        == "ransomware"
    )


    # --------------------------------------
    # Store latest result
    # --------------------------------------

    latest_detection = {

        "prediction": prediction,

        "normal_probability":
            normal_probability,

        "ransomware_probability":
            ransomware_probability,

        "alert": alert,

        "file": suspicious_file,

        "timestamp":
            datetime.now().isoformat()
    }


    # --------------------------------------
    # Return result
    # --------------------------------------

    return {

        "status": "updated",

        "data": latest_detection
    }