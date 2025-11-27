import random

# Simulated ML prediction function
def predict_crime_pattern(description):
    """
    Fake ML model: predicts likely crime type from description.
    Replace this logic later with an actual model.
    """
    patterns = [
        "Theft", 
        "Assault", 
        "Fraud", 
        "Cyber Crime", 
        "Domestic Violence", 
        "Drug Abuse"
    ]
    predicted_type = random.choice(patterns)
    confidence = round(random.uniform(0.75, 0.98), 2)
    return {
        "predicted_type": predicted_type,
        "confidence": confidence
    }
