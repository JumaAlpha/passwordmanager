import re

def check_password_strength(password):
    """Check the strength of a password and return a strength level."""
    if len(password) < 8:
        return "Weak", 20  # Too short
    elif not re.search("[a-z]", password):
        return "Weak", 40  # No lowercase letters
    elif not re.search("[A-Z]", password):
        return "Weak", 60  # No uppercase letters
    elif not re.search("[0-9]", password):
        return "Weak", 80  # No digits
    elif not re.search("[!@#$%^&*(),.?\":{}|<>]", password):
        return "Moderate", 85  # No special characters
    else:
        return "Strong", 100  # All criteria met

# Example usage
if __name__ == "__main__":
    password = "SecurePass123!"
    strength, score = check_password_strength(password)
    print(f"Password: {password} | Strength: {strength} | Score: {score}%")
