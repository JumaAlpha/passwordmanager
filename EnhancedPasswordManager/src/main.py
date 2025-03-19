import tkinter as tk
from tkinter import messagebox
# from ui import create_ui
from ui import create_login_ui
from auth import save_credentials
from security import encrypt_password, decrypt_password, get_encryption_key  # Importing the required functions
import random
import string
from auth import validate_credentials, save_credentials
import os
from database import (
    create_backup, 
    restore_from_backup, 
    get_all_passwords, 
    save_password_to_database,
    delete_password_from_database
)

encryption_key = os.urandom(32)

def main():
    root = tk.Tk()
    root.title("Enhanced Password Manager")

    # Set the window size (optional)
    root.geometry("400x500")

    # Create the user interface
    create_login_ui(root)

    # Start the Tkinter event loop
    root.mainloop()

# Save an admin account
save_credentials("admin", "password")

if __name__ == "__main__":
    main()
