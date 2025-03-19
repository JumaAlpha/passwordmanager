import os
import hashlib
import json

# Path for storing the login credentials
CREDENTIALS_FILE = "credentials.json"

def hash_password(password):
    """Hash the password using SHA-256 for basic security."""
    return hashlib.sha256(password.encode()).hexdigest()

def save_credentials(username, password):
    """Save the hashed username and password to a file."""
    credentials = {
        "username": username,
        "password": hash_password(password)
    }
    with open(CREDENTIALS_FILE, "w") as f:
        json.dump(credentials, f)

def load_credentials():
    """Load the credentials from the file."""
    if os.path.exists(CREDENTIALS_FILE):
        with open(CREDENTIALS_FILE, "r") as f:
            return json.load(f)
    else:
        return None

def validate_credentials(username, password):
    """Check if the entered credentials match the saved ones."""
    stored_credentials = load_credentials()
    if stored_credentials:
        hashed_password = hash_password(password)
        return stored_credentials["username"] == username and stored_credentials["password"] == hashed_password
    return False
