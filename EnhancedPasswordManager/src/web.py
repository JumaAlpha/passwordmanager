from flask import Flask, render_template, request, redirect, url_for, session, flash
from auth import validate_credentials, save_credentials  # Handles user authentication
from database import save_password_to_database, get_all_passwords  # Manages password storage
from utils import check_password_strength  # Validates password strength
from security import encrypt_password, decrypt_password, get_encryption_key# Security functions
import os

# Load encryption key from environment variable or generate one if it doesn't exist
encryption_key = get_encryption_key()  # Get the encryption key

# Initialize Flask application
app = Flask(__name__)
app.secret_key = os.urandom(24)  # Secure session management

# Initialize an admin account if not present
if not os.path.exists("credentials.json"):
    save_credentials("admin", "password")

# Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if validate_credentials(username, password):
            session['username'] = username
            return redirect(url_for('dashboard'))
        flash("Invalid username or password, please try again.")
    return render_template('login.html')

# Dashboard Route
@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    # Retrieve and decrypt passwords for display
    passwords = get_all_passwords()  # Fetches (service, email, username, encrypted_password) tuples
    decrypted_passwords = []
    for service, email, username, encrypted_password in passwords:
        try:
            # Decrypt the password using the encryption key
            decrypted_password = decrypt_password(encrypted_password, encryption_key)
            decrypted_passwords.append((service, email, username, decrypted_password))
        except Exception as e:
            flash(f"Error decrypting password for service: {service} - {str(e)}")
            decrypted_passwords.append((service, email, username, "[Decryption Error]"))
    
    return render_template('dashboard.html', passwords=decrypted_passwords)

# Add Password Route
@app.route('/add_password', methods=['GET', 'POST'])
def add_password():
    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        service = request.form['service']
        email = request.form['email']
        username = request.form['username']
        password = request.form['password']
        strength, score = check_password_strength(password)

        if score < 80:
            flash("Password strength must be at least 80% to save.")
            return render_template('add_password.html')

        # Encrypt and save password
        encrypted_password = encrypt_password(password, encryption_key)
        save_password_to_database(service, email, username, encrypted_password)
        flash("Password saved successfully!")
        return redirect(url_for('dashboard'))
    return render_template('add_password.html')

# Logout Route
@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

# Generate Secure Password Route (optional)
@app.route('/generate_password', methods=['GET', 'POST'])
def generate_password():
    if request.method == 'POST':
        length = request.form.get('length', type=int, default=12)
        new_password = generate_secure_password(length)
        return render_template('generate_password.html', new_password=new_password)
    return render_template('generate_password.html')

# Run the application
if __name__ == '__main__':
    app.run(debug=True)
