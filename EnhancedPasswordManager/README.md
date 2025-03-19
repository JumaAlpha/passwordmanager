# Enhanced Password Manager

## Overview

The project EnhancedPasswordManager is a secure, user-friendly cross-platform application designed to aid users in storage and managing of their passwords effectively. The application prioritizes robust encryption and secure authentication methods, aiming to protect against various attacks, including brute force attempts.

## Key Features

- **Secure Authentication**: User login management with bcrypt hashing.
- **Password Generation**: Random password generation with customizable options.
- **Password Strength Meter**: Visual feedback on password strength.
- **Database Operations**: Save, retrieve, and delete passwords securely.
- **Backup and Restore**: Create backups of stored passwords and restore from them.

## Installation

### Prerequisites

- Python 3.6 or higher
- `pip` (Python package installer)

### Dependencies

Install the required libraries using pip:


### Project Structure

EnhancedPasswordManager/
│
├── src/
│   ├── __init__.py
│   ├── auth.py           # Manages user authentication
│   ├── database.py       # Handles database operations
│   ├── main.py           # Main entry point for the application
│   ├── security.py       # Password hashing and encryption functions
│   └── ui.py             # User interface components
│
├── tests/                # Test files for the application
│   ├── test_security.py
│   └── test_ui.py
│
├── database/
│   └── passwords.xlsx    # File for storing passwords
│
├── requirements.txt       # List of dependencies
├── README.md              # Project documentation
└── setup.py               # Package configuration
```

## Usage

1. **Run the Application**: Start the application by executing the `main.py` script.


   python src/main.py

2. **Login**: Use the credentials defined in `credentials.json` to log in. Default credentials are:

   - Username: `admin`
   - Password: `password`

3. **Manage Passwords**:
   - Add a new password by filling in the service, email, username, and password fields.
   - View saved passwords in the "View Saved Passwords" section.
   - Create backups of your password database and restore from them when needed.

## Code Overview

### Authentication

- The `auth.py` module manages user login authentication. It validates credentials against stored hashed passwords in the credentials.json
### Security

- The `security.py` module handles password hashing using bcrypt and encrypts passwords with AES encryption.

### User Interface

- The `ui.py` module contains the Tkinter GUI for the application, providing a user-friendly interface for interaction.

### Database Management

- The `database.py` module manages database operations, including saving, retrieving, and deleting passwords.
