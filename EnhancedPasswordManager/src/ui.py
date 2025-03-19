import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from database import (
    create_backup,
    restore_from_backup,
    get_all_passwords,
    save_password_to_database,
    delete_password_from_database
)
from utils import check_password_strength
from security import encrypt_password, decrypt_password, get_encryption_key  # Importing the required functions
import random
import string
from auth import validate_credentials
import os

# Generate or retrieve the encryption key
encryption_key = get_encryption_key()  # Function handles key retrieval or creation

def generate_password(length=12, include_special_chars=True):
    """Generate a random password."""
    characters = string.ascii_letters + string.digits
    if include_special_chars:
        characters += string.punctuation

    password = ''.join(random.choice(characters) for _ in range(length))
    return password

def create_login_ui(root):
    root.title("Login")
    root.geometry("300x200")

    def login():
        username = username_entry.get()
        password = password_entry.get()

        if validate_credentials(username, password):
            root.destroy()  # Close the login window
            main_ui()  # Open the main UI
        else:
            messagebox.showerror("Login Error", "Invalid username or password.")

    ttk.Label(root, text="Username:").pack(pady=(20, 5))
    username_entry = ttk.Entry(root)
    username_entry.pack(pady=(0, 10))

    ttk.Label(root, text="Password:").pack(pady=(5, 5))
    password_entry = ttk.Entry(root, show='*')
    password_entry.pack(pady=(0, 10))

    login_button = ttk.Button(root, text="Login", command=login)
    login_button.pack(pady=(10, 0))

    root.mainloop()

def main_ui():
    root = tk.Tk()
    create_ui(root)

def create_ui(root):
    root.title("Enhanced Password Manager")
    root.geometry("350x400")
    root.resizable(False, False)

    style = ttk.Style()
    style.configure("TLabel", font=("Arial", 10))
    style.configure("TEntry", font=("Arial", 10))
    style.configure("TButton", font=("Arial", 10))
    style.configure("Treeview", font=("Arial", 10))
    style.configure("Treeview.Heading", font=("Arial", 12, "bold"))

    main_frame = ttk.Frame(root, padding="20")
    main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

    input_frame = ttk.Frame(main_frame)
    input_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 20))

    labels = ["Service:", "Email:", "Username:", "Password:"]
    entries = []

    for i, label in enumerate(labels):
        ttk.Label(input_frame, text=label).grid(column=0, row=i, sticky=tk.W, pady=(5, 0))
        entry = ttk.Entry(input_frame)
        entry.grid(column=1, row=i, sticky=(tk.W, tk.E), pady=(6, 0))
        entries.append(entry)

    service_entry, email_entry, username_entry, password_entry = entries

    def toggle_password_visibility():
        if password_entry.cget('show') == '*':
            password_entry.config(show='')
            eye_button.config(text='👁️')
        else:
            password_entry.config(show='*')
            eye_button.config(text='👁️‍🗨️')

    eye_button = ttk.Button(input_frame, text='👁️‍🗨️', command=toggle_password_visibility, width=2)
    eye_button.grid(column=2, row=3, padx=(5, 0))

    strength_label = ttk.Label(input_frame, text="Strength: N/A")
    strength_label.grid(column=0, row=4, columnspan=3, pady=(5, 0))

    def check_strength(event=None):
        password = password_entry.get()
        strength, score = check_password_strength(password)
        if score < 40:
            strength_label.config(text="Strength: Weak")
        elif score < 70:
            strength_label.config(text="Strength: Moderate")
        else:
            strength_label.config(text="Strength: Strong")

    password_entry.bind('<Key>', check_strength)

    action_frame = ttk.Frame(main_frame)
    action_frame.grid(row=1, column=0, pady=(10, 0))

    def save_password():
        service = service_entry.get()
        email = email_entry.get()
        username = username_entry.get()
        password = password_entry.get()

        strength, score = check_password_strength(password)
        if score < 80:
            messagebox.showwarning("Warning", "Password strength must be at least 80% to save.")
            return

        if service and email and username and password:
            encrypted_password = encrypt_password(password, encryption_key)  # Encrypt the password
            save_password_to_database(service, email, username, encrypted_password)
            messagebox.showinfo("Success", "Password saved successfully!")
            for entry in entries:
                entry.delete(0, tk.END)
        else:
            messagebox.showwarning("Warning", "Please fill in all fields.")

    save_button = ttk.Button(action_frame, text="Save Password", command=save_password)
    save_button.grid(column=0, row=0, padx=10)

    generate_button = ttk.Button(action_frame, text="🔁", command=lambda: password_entry.insert(0, generate_password()))
    generate_button.grid(column=1, row=0, padx=10)

    backup_frame = ttk.Frame(main_frame)
    backup_frame.grid(row=2, column=0, pady=(10, 0))

    backup_button = ttk.Button(backup_frame, text="Backup Passwords", command=create_backup)
    backup_button.grid(column=0, row=0, padx=10)

    def restore_database():
        backup_file = filedialog.askopenfilename(title="Select Backup File", filetypes=[("CSV files", "*.csv")])
        if backup_file:
            restore_from_backup(backup_file)
            messagebox.showinfo("Success", "Database restored successfully!")

    restore_button = ttk.Button(backup_frame, text="Restore from Backup", command=restore_database)
    restore_button.grid(column=1, row=0, padx=10)

    view_frame = ttk.Frame(main_frame)
    view_frame.grid(row=3, column=0, pady=(10, 0))
    
    def view_passwords():
        passwords_window = tk.Toplevel(root)
        passwords_window.title("Saved Passwords")

        columns = ('Service', 'Email', 'Username', 'Password')
        tree = ttk.Treeview(passwords_window, columns=columns, show='headings')

        for col in columns:
            tree.heading(col, text=col)
            tree.column(col, minwidth=100, width=120, stretch=tk.YES)

        tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        def copy_password(event):
            selected_item = tree.selection()
            if selected_item:
                password = tree.item(selected_item, "values")[3]
                root.clipboard_clear()
                root.clipboard_append(password)
                messagebox.showinfo("Copied", "Password copied to clipboard!")

        tree.bind("<Button-3>", copy_password)

        passwords = get_all_passwords()
        print("Encrypted passwords retrieved:", passwords)

        for service, email, username, encrypted_password in passwords:
            try:
                # Decrypt using the same encryption key
                decrypted_password = decrypt_password(encrypted_password, encryption_key)  # Decrypt the password
                print(f"Decrypted password for {service}: {decrypted_password}")
                tree.insert('', tk.END, values=(service, email, username, decrypted_password))
            except Exception as e:
                print(f"Error decrypting password for {service}: {e}")
                messagebox.showerror("Error", f"Failed to decrypt password for {service}")

        def delete_password_from_tree():
            selected_item = tree.selection()
            if selected_item:
                service = tree.item(selected_item)["values"][0]
                username = tree.item(selected_item)["values"][2]
                confirm = messagebox.askyesno("Confirm Deletion", f"Are you sure you want to delete the password for '{service}' with username '{username}'?")
                
                if confirm:
                    delete_password_from_database(service, username)
                    tree.delete(selected_item)

        delete_button = ttk.Button(passwords_window, text="Delete Selected", command=delete_password_from_tree)
        delete_button.grid(row=1, column=0, pady=(5, 0))

    view_button = ttk.Button(view_frame, text="View Saved Passwords", command=view_passwords)
    view_button.grid(column=0, row=0, padx=10)

    root.mainloop()

if __name__ == "__main__":
    login_window = tk.Tk()
    create_login_ui(login_window)
