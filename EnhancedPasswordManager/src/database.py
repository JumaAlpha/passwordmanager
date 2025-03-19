import pandas as pd
import os
import shutil
import datetime
import tkinter as tk
from tkinter import messagebox

# File path for storing passwords
FILE_PATH = 'database/passwords.csv'
BACKUP_DIR = 'database/backups'

# Function to read passwords from the CSV file
def read_passwords(file_path=FILE_PATH):
    """Reads the CSV file containing passwords and returns it as a pandas DataFrame."""
    if not os.path.exists(file_path):
        print(f"File not found: {file_path}")
        return pd.DataFrame(columns=['Service', 'Email', 'Username', 'Password'])
    
    try:
        df = pd.read_csv(file_path)
        return df
    except Exception as e:
        print(f"Error reading the file: {e}")
        return pd.DataFrame(columns=['Service', 'Email', 'Username', 'Password'])

# Function to write (append) passwords to the CSV file
def write_passwords(new_entry, file_path=FILE_PATH):
    """Appends new password entries to the CSV file."""
    try:
        if os.path.exists(file_path):
            df_existing = pd.read_csv(file_path)
        else:
            df_existing = pd.DataFrame(columns=new_entry.keys())

        df_new = pd.DataFrame(new_entry)
        df_combined = pd.concat([df_existing, df_new], ignore_index=True)

        df_combined.to_csv(file_path, index=False)
        print("Password saved successfully!")
    except Exception as e:
        print(f"Error writing to the file: {e}")

# Function to save a password entry to the database
def save_password_to_database(service, email, username, password):
    """Saves a new password entry to the database (CSV file)."""
    new_entry = {
        'Service': [service],
        'Email': [email],
        'Username': [username],
        'Password': [password]
    }
    write_passwords(new_entry)

# Function to retrieve all passwords from the database
def get_all_passwords(file_path=FILE_PATH):
    """Retrieves all passwords from the database (CSV file)."""
    df = read_passwords(file_path)
    return df.values.tolist()

def delete_password_from_database(service, username):
    """Deletes a specific password entry from the database (CSV file) after user confirmation."""
    # Initialize Tkinter root (but hide the main window)
    root = tk.Tk()
    root.withdraw()  # Hide the root window

    df = read_passwords(FILE_PATH)

    if df.empty:
        messagebox.showinfo("No Passwords", "No passwords to delete.")
        return

    # Check if the service and username exist in the DataFrame
    if not ((df['Service'] == service) & (df['Username'] == username)).any():
        messagebox.showinfo("No Entry Found", f"No entry found for service: {service} with username: {username}")
        return

    # Show the confirmation dialog box
    confirm = messagebox.askyesno("Confirm Deletion", f"Are you sure you want to delete the password for {service} (username: {username})?")

    if not confirm:
        messagebox.showinfo("Deletion Canceled", "Password deletion was canceled.")
        return

    # Proceed with deletion
    df = df[~((df['Service'] == service) & (df['Username'] == username))]
    df.to_csv(FILE_PATH, index=False)
    
    messagebox.showinfo("Success", f"Password for {service} (username: {username}) deleted successfully.")
    # print(f"Password for {service} (username: {username}) deleted successfully.")

# Backup function
def create_backup(file_path=FILE_PATH):
    """Creates a backup of the password database."""
    if not os.path.exists(BACKUP_DIR):
        os.makedirs(BACKUP_DIR)

    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M')
    backup_file_path = os.path.join(BACKUP_DIR, f'passwords_backup_{timestamp}.csv')

    try:
        shutil.copy(file_path, backup_file_path)
        print(f"Backup created successfully at: {backup_file_path}")
    except Exception as e:
        print(f"Error creating backup: {e}")

# Restore function
def restore_from_backup(backup_file):
    """Restores the password database from a backup file."""
    if os.path.exists(backup_file):
        try:
            shutil.copy(backup_file, FILE_PATH)
            print(f"Database restored successfully from: {backup_file}")
        except Exception as e:
            print(f"Error restoring database: {e}")
    else:
        print(f"Backup file not found: {backup_file}")

# Example usage
if __name__ == "__main__":
    # Test saving a password
    save_password_to_database('example.com', 'user@example.com', 'user123', 'securepassword123')

    # Test reading passwords
    passwords = get_all_passwords()
    print(passwords)

    # Test deleting a password
    delete_password_from_database('example.com')
    
    # Display passwords after deletion
    passwords_after_deletion = get_all_passwords()
    print(passwords_after_deletion)
