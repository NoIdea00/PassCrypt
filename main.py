from tkinter import Tk, Label, Entry, Button, StringVar, Frame, Checkbutton, IntVar
import base64
from email import encoders
from email.mime.base import MIMEBase
from email.mime.text import MIMEText
import os
import re
import time
import sys
from dotenv import load_dotenv
from tkinter import *
from tkinter import messagebox
from tkinter import simpledialog
import sqlite3
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import pyperclip
import random
import string
import smtplib
from email.message import EmailMessage
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
import secrets

class ToolTip(object):

    def __init__(self, widget):
        self.widget = widget
        self.tip_window = None
        self.id = None
        self.x = self.y = 0

    def show_tooltip_win(self, text):
        "Display text in tooltip window"
        self.text = text
        if self.tip_window or not self.text:
            return
        x, y, cx, cy = self.widget.bbox("insert")
        x = x + self.widget.winfo_rootx() + 57
        y = y + cy + self.widget.winfo_rooty() +27
        self.tip_window = tip_win = Toplevel(self.widget)
        tip_win.wm_overrideredirect(1)
        tip_win.wm_geometry("+%d+%d" % (x, y))
        label = Label(tip_win, text=self.text, justify=LEFT,
                      background="#ffffe0", relief=SOLID, borderwidth=1,
                      font=("tahoma", "8", "normal"))
        label.pack(ipadx=1)

    def hide_tooltip_win(self):
        tip_win = self.tip_window
        self.tip_window = None
        if tip_win:
            tip_win.destroy()

def CreateToolTip(widget, text):
    toolTip = ToolTip(widget)
    def enter(event):
        toolTip.show_tooltip_win(text)
    def leave(event):
        toolTip.hide_tooltip_win()
    widget.bind('<Enter>', enter)
    widget.bind('<Leave>', leave)

# Creating window
root = Tk()
root.title("PassCrypt Password Manager")
root.geometry("700x700")
root.resizable(False, False)
root.config(bg="grey")

env_path = ".env"
if getattr(sys, 'frozen', False):
    env_path = os.path.join(sys._MEIPASS, ".env")
load_dotenv(env_path)


root_path = __file__

# get basename of root_path
root_path = os.path.basename(root_path)

# Creating database
database_path = os.path.join(os.path.dirname(root_path), "password_manager.db")

conn = sqlite3.connect(database_path)
c = conn.cursor()

# Creating tables
c.execute("""CREATE TABLE IF NOT EXISTS users(
            username TEXT,
            password TEXT,
            email TEXT
            )""")

c.execute("""CREATE TABLE IF NOT EXISTS password_manager(
            website TEXT,
            username TEXT,
            password TEXT
            )""")

conn.commit()



key_file_path = os.path.join(os.path.dirname(root_path), "key.key")
key = None


def generate_key():
    return os.urandom(32)


def store_key(key):
    with open(key_file_path, "wb") as key_file:
        key_file.write(key)


def get_key():
    try:
        with open(key_file_path, "rb") as key_file:
            return key_file.read()
    except FileNotFoundError:
        return None


key = get_key()
if key is None:
    key = generate_key()
    store_key(key)


# Global variables
logged_in = False
password_visibility = False
password_viewing = False
login_attempts = 0
login_disabled_until = 0
last_2fa_request_time = 0


# Creating functions

def switch_frame(frame):
    clear_entries()
    frame.tkraise()

 
def is_valid_email(email):
    # Use a regular expression to validate the email format
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email)

def register():
    # Retrieve username, password, and email from the user
    username = register_username_entry.get()
    password = register_password_entry.get()
    email = register_email_entry.get()

    # Check if any of the fields are empty
    if not username or not password or not email:
        messagebox.showerror("Error", "Please fill in all the fields!")
        return

    # Check if the email is valid
    if not is_valid_email(email):
        messagebox.showerror("Error", "Invalid email address format!")
        return

    # Check if the username is available
    if is_username_available(username):
        # Check if the email is already registered
        if is_email_registered(email):
            messagebox.showerror("Error", "Email is already registered!")
        else:
            # Generate a verification code and its expiry timestamp
            verification_code = ''.join(random.choice(string.digits) for _ in range(6))
            verification_code_expiry = time.time() + 300  # Set expiry time to 5 minutes from now

            # Send the verification code via email
            send_register_verification_email(email, verification_code)

            # Prompt the user to enter the verification code
            entered_code = simpledialog.askstring("Verification", "Enter the verification code sent to your email:")

            # Check the validity of the verification code
            if entered_code == verification_code and time.time() <= verification_code_expiry:
                # Store the credentials
                store_credentials(username, password, email)
                messagebox.showinfo("Success", "User registered successfully!")
                send_registration_email(username, email)
            else:
                messagebox.showerror("Error", "Invalid or expired verification code!")
    else:
        messagebox.showerror("Error", "Username is not available! Register another username.")

def is_email_registered(email):
    # Implement your logic to check if the email is already registered
    c.execute("SELECT * FROM users WHERE email = ?", (email,))
    user = c.fetchone()

    if user:
        return True

    return False


def send_registration_email(username, email):
    # Create a message object
    msg = EmailMessage()
    
    # Set the subject and recipient
    msg["Subject"] = "Registration Successful"
    msg["To"] = email
    
    # Compose the email body
    body = f"Dear {username},\n\nThank you for registering on our password manager application!\n\n" \
           "Your registration was successful.\n\nBest regards,\nThe PassCrypt Team"
    msg.set_content(body)
    
    # Set up the email server
    smtp_server = os.getenv("SMTP_SERVER")
    smtp_port = int(os.getenv("SMTP_PORT"))
    smtp_username = os.getenv("SMTP_USERNAME")
    smtp_password = os.getenv("SMTP_PASSWORD")
    
    # Connect to the email server
    with smtplib.SMTP(smtp_server, smtp_port) as server:
        server.starttls()
        server.login(smtp_username, smtp_password)
        
        # Send the email
        server.send_message(msg)


def send_register_verification_email(email, verification_code):
    # Create a message object
    msg = EmailMessage()
    
    # Set the subject and recipient
    msg["Subject"] = "Register Verification Code"
    msg["To"] = email
    
    # Compose the email body
    body = f"Your verification code for register is: {verification_code}\n\n" \
           "Please use the above code within 5 minutes to complete the registration process."
    msg.set_content(body)
    
    # Set up the email server
    smtp_server = os.getenv("SMTP_SERVER")
    smtp_port = int(os.getenv("SMTP_PORT"))
    smtp_username = os.getenv("SMTP_USERNAME")
    smtp_password = os.getenv("SMTP_PASSWORD")
    
    # Connect to the email server
    with smtplib.SMTP(smtp_server, smtp_port) as server:
        server.starttls()
        server.login(smtp_username, smtp_password)
        
        # Send the email
        server.send_message(msg)
    
    


def send_login_verification_email(email, verification_code):
    # Create a message object
    msg = EmailMessage()
    
    # Set the subject and recipient
    msg["Subject"] = "Login Verification Code"
    msg["To"] = email
    
    # Compose the email body
    body = f"Your verification code for login is: {verification_code}\n" \
           "If you did not request this, please change your password immediately.\n"\
            "Please use the above code within 5 minutes to complete the login process."
    msg.set_content(body)
    
    # Set up the email server
    smtp_server = os.getenv("SMTP_SERVER")
    smtp_port = int(os.getenv("SMTP_PORT"))
    smtp_username = os.getenv("SMTP_USERNAME")
    smtp_password = os.getenv("SMTP_PASSWORD")
    
    # Connect to the email server
    with smtplib.SMTP(smtp_server, smtp_port) as server:
        server.starttls()
        server.login(smtp_username, smtp_password)
        
        # Send the email
        server.send_message(msg)


def send_delete_verification_email(email, verification_code):    
    # Create a message object
    msg = EmailMessage()
    
    # Set the subject and recipient
    msg["Subject"] = "Authorize To Delete Saved Password Verification Code"
    msg["To"] = email
    
    # Compose the email body
    body = f"Your verification code for password record deletion is: {verification_code}\n" \
           "If you did not request this, please change your password immediately.\n"\
           "The Verification code will expire in 5 minutes."
    msg.set_content(body)
    
    # Set up the email server
    smtp_server = os.getenv("SMTP_SERVER")
    smtp_port = int(os.getenv("SMTP_PORT"))
    smtp_username = os.getenv("SMTP_USERNAME")
    smtp_password = os.getenv("SMTP_PASSWORD")
    
    # Connect to the email server
    with smtplib.SMTP(smtp_server, smtp_port) as server:
        server.starttls()
        server.login(smtp_username, smtp_password)
        
        # Send the email
        server.send_message(msg)

def send_verification_email(email, verification_code): 
    # Create a message object
    msg = EmailMessage()
    
    # Set the subject and recipient
    msg["Subject"] = "Account Setting Verification Code"
    msg["To"] = email
    
    # Compose the email body
    body = f"Your verification code for making changes on your password manager account is: {verification_code}\n" \
           "If you did not request this, please change your password immediately.\n"\
           "The Verification code will expire in 5 minutes."
    msg.set_content(body)
    
    # Set up the email server
    smtp_server = os.getenv("SMTP_SERVER")
    smtp_port = int(os.getenv("SMTP_PORT"))
    smtp_username = os.getenv("SMTP_USERNAME")
    smtp_password = os.getenv("SMTP_PASSWORD")
    
    # Connect to the email server
    with smtplib.SMTP(smtp_server, smtp_port) as server:
        server.starttls()
        server.login(smtp_username, smtp_password)
        
        # Send the email
        server.send_message(msg)

def send_database_backup(email):
    try:
        # Create a backup of the database
        backup_file = "password_manager_backup.txt"
        with open(backup_file, "w") as f:
            c.execute("SELECT * FROM password_manager")
            password_records = c.fetchall()
            for record in password_records:
                website = record[0]
                username = record[1]
                encrypted_password = record[2]
                decrypted_password = decrypt_password(encrypted_password)
                f.write(f"Website: {website} - Username: {username} - Password: {decrypted_password}\n")

        # Close the backup file before sending the email
        f.close()

        # Set up the email message
        smtp_server = os.getenv("SMTP_SERVER")
        smtp_port = os.getenv("SMTP_PORT")
        smtp_username = os.getenv("SMTP_USERNAME")
        smtp_password = os.getenv("SMTP_PASSWORD")

        msg = MIMEMultipart()
        msg['From'] = smtp_username
        msg['To'] = email
        msg['Subject'] = "PassCrypt Password Manager Backup"

        body = "Here is your backup file from PassCrypt Password Manager."
        msg.attach(MIMEText(body, 'plain'))

        attachment = open(backup_file, "rb")
        part = MIMEBase('application', 'octet-stream')
        part.set_payload((attachment).read())
        encoders.encode_base64(part)
        part.add_header('Content-Disposition', "attachment; filename= " + backup_file)
        msg.attach(part)

        # Send the email
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(smtp_username, smtp_password)
            server.sendmail(smtp_username, email, msg.as_string())
            
        # Display success message and delete the backup file
        messagebox.showinfo("Backup Sent", "Database backup has been sent successfully!")
        root.after(3000,lambda:os.remove(backup_file))
    except Exception as e:
        # Display error message if backup sending failed
        messagebox.showerror("Backup Failed", f"Failed to send database backup.\nError: {str(e)}")

def send_reset_email(email, reset_code):
    # Create a message object
    msg = EmailMessage()
    
    # Set the subject and recipient
    msg["Subject"] = "Reset Code"
    msg["To"] = email
    
    # Compose the email body
    body = f"Your reset code is: {reset_code}\n\n" \
           "Please use the above code within 5 minutes to reset your password."
    msg.set_content(body)
    
    # Set up the email server
    smtp_server = os.getenv("SMTP_SERVER")
    smtp_port = int(os.getenv("SMTP_PORT"))
    smtp_username = os.getenv("SMTP_USERNAME")
    smtp_password = os.getenv("SMTP_PASSWORD")
    
    # Connect to the email server
    with smtplib.SMTP(smtp_server, smtp_port) as server:
        server.starttls()
        server.login(smtp_username, smtp_password)
        
        # Send the email
        server.send_message(msg)
   
def send_reset_password_success_email(email):
    # Create a message object
    msg = EmailMessage()
    
    # Set the subject and recipient
    msg["Subject"] = "Password Reset Successful"
    msg["To"] = email
    
    # Compose the email body
    body = f"Your password has been reset successfully!\n\n" \
           "If you did not request this, please change your password immediately."
    msg.set_content(body)
    
    # Set up the email server
    smtp_server = os.getenv("SMTP_SERVER")
    smtp_port = int(os.getenv("SMTP_PORT"))
    smtp_username = os.getenv("SMTP_USERNAME")
    smtp_password = os.getenv("SMTP_PASSWORD")
    
    # Connect to the email server
    with smtplib.SMTP(smtp_server, smtp_port) as server:
        server.starttls()
        server.login(smtp_username, smtp_password)
        
        # Send the email
        server.send_message(msg)

def generate_reset_code():
    reset_code_length = 8  # Set the desired length of the reset code
    reset_code_characters = string.ascii_letters + string.digits
    reset_code = ''.join(secrets.choice(reset_code_characters) for _ in range(reset_code_length))
    return reset_code

def update_password(username, new_password):
    # Encrypt the new password
    encrypted_new_password = encrypt_password(new_password)
    
    # Update the password in the database
    c.execute("UPDATE users SET password = ? WHERE username = ?", (encrypted_new_password, username))
    conn.commit()



# def login():
#     global logged_in, login_attempts, login_disabled_until, current_username, current_email

#     # Disable the login button if too many attempts have been made
#     if login_attempts >= 3:
#         if time.time() < login_disabled_until:
#             remaining_time = int(login_disabled_until - time.time())
#             messagebox.showerror("Error", f"Too many login attempts. Try again in {remaining_time} seconds.")
#             return

#     username = username_entry.get()
#     password = password_entry.get()

#     # Check if username and password fields are not empty
#     if not username or not password:
#         messagebox.showerror("Error", "Please enter both username and password.")
#         return

#     if check_credentials(username, password):
#         # Generate a verification code and its expiry timestamp
#         verification_code = ''.join(random.choice(string.digits) for _ in range(6))
#         verification_code_expiry = time.time() + 300  # Set expiry time to 5 minutes from now
        
#         # Retrieve the user's email
#         c.execute("SELECT email FROM users WHERE username = ?", (username,))
#         email = c.fetchone()[0]  # Assign the email value here
        
#         # Send the verification code via email
#         send_login_verification_email(email, verification_code)
        
#         # Prompt the user to enter the verification code
#         entered_code = simpledialog.askstring("Verification", "Enter the verification code sent to your email:")
        
#         # Check the validity of the verification code
#         if entered_code == verification_code and time.time() <= verification_code_expiry:
#             logged_in = True
            
#             # Store the current username and email
#             current_username = username
#             current_email = email

#             # Update the user info in the Settings frame
#             update_user_info(current_username, current_email)
            
#             switch_frame(password_manager_frame)
#             clear_entries()
#         else:
#             messagebox.showerror("Error", "Invalid or expired verification code!")
#     else:
#         login_attempts += 1

#         if login_attempts >= 3:
#             login_disabled_until = time.time() + 5  # Disable login for 5 seconds
#             login_attempts = 0  # Reset login attempts
            
#             messagebox.showerror("Error", "Too many login attempts. Try again in 5 seconds.")
#             login_button.config(state="disabled")
#             username_entry.config(state="disabled")
#             password_entry.config(state="disabled")

#             # Re-enable the login button after 5 seconds
#             root.after(5000, enable_login_button)

#         else:
#             messagebox.showerror("Error", "Invalid username or password.")

def login():
    global logged_in, login_attempts, login_disabled_until, current_username, current_email

    # Disable the login button if too many attempts have been made
    if login_attempts >= 3:
        if time.time() < login_disabled_until:
            remaining_time = int(login_disabled_until - time.time())
            messagebox.showerror("Error", f"Too many login attempts. Try again in {remaining_time} seconds.")
            return

    username = username_entry.get()
    password = password_entry.get()

    # Check if username and password fields are not empty
    if not username or not password:
        messagebox.showerror("Error", "Please enter both username and password.")
        return

    if check_credentials(username, password):
        logged_in = True

        # Store the current username and email
        current_username = username
        current_email = None  # Remove the email assignment

        # Update the user info in the Settings frame
        update_user_info(current_username, current_email)
        
        switch_frame(password_manager_frame)
        clear_entries()
    else:
        login_attempts += 1

        if login_attempts >= 3:
            login_disabled_until = time.time() + 5  # Disable login for 5 seconds
            login_attempts = 0  # Reset login attempts
            
            messagebox.showerror("Error", "Too many login attempts. Try again in 5 seconds.")
            login_button.config(state="disabled")
            username_entry.config(state="disabled")
            password_entry.config(state="disabled")

            # Re-enable the login button after 5 seconds
            root.after(5000, enable_login_button)

        else:
            messagebox.showerror("Error", "Invalid username or password.")



def enable_login_button():
    login_button.config(state="normal")
    username_entry.config(state="normal")
    password_entry.config(state="normal")
    login_attempts = 0  

def update_user_info(username, email):
    user_info_label.config(text=f"Current Logged In Username: {username}\nCurrent Logged In Email: {email}")


def clear_login_fields():
    username_entry.delete(0, END)
    password_entry.delete(0, END)

def forgot_password():
    # Prompt the user to enter their email
    email = simpledialog.askstring("Forgot Password", "Enter your email:")
    if email is None:
        return

    # Check if the email is valid
    c.execute("SELECT email FROM users WHERE email = ?", (email,))
    result = c.fetchone()
    if result is None:
        messagebox.showerror("Error", "Email not found!")
        return

    # Generate a reset code
    reset_code = generate_reset_code()

    # Send the reset code via email
    send_reset_email(email, reset_code)

    # Prompt the user to enter the received reset code
    entered_reset_code = simpledialog.askstring("Forgot Password", "Enter the reset code:")
    if entered_reset_code is None:
        return

    # Check if the entered reset code matches the generated reset code
    if entered_reset_code != reset_code:
        messagebox.showerror("Error", "Invalid reset code!")
        return

    # Prompt the user to enter a new password
    new_password = simpledialog.askstring("Forgot Password", "Enter a new password:", show="*")
    if new_password is None:
        return

    # Prompt the user to confirm the new password
    confirm_new_password = simpledialog.askstring("Forgot Password", "Confirm the new password:", show="*")
    if confirm_new_password is None:
        return

    # Check if the new password and confirmation match
    if new_password != confirm_new_password:
        messagebox.showerror("Error", "Passwords do not match!")
        return

    # Update the password in the database
    c.execute("UPDATE users SET password = ? WHERE email = ?", (encrypt_password(new_password), email))
    conn.commit()
    messagebox.showinfo("Success", "Password reset successfully!")
    send_reset_password_success_email(email)


def is_valid_email(email):
    # Implement a validation check for email format
    return "@" in email and "." in email



def logout():
    global logged_in
    logged_in = False

    # Check if the user wants to send a backup of the database
    send_backup = messagebox.askyesno("Send Backup", "Do you want to send a backup of your database to your email?")

    if send_backup:
        # Retrieve user's email
        c.execute("SELECT email FROM users WHERE username = ?", (username_entry.get(),))
        email = c.fetchone()[0]

        # Send the database backup to the user's email
        send_database_backup(email)

    # Clear the username and password fields
    username_entry.delete(0, END)
    password_entry.delete(0, END)

    # Switch to the login frame
    switch_frame(login_frame)

def generate_password():
    # Generate a random password with a combination of letters, digits, and special characters
    password_length = random.randint(8, 16)  # Generate a random password length between 8 and 16
    password_characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(password_characters) for _ in range(password_length))

    # Insert the generated password into the password entry field
    pm_password_entry.config(state="normal")  # Enable the entry field to modify its content
    pm_password_entry.delete(0, END)
    pm_password_entry.insert(0, password)
    pm_password_entry.config(state="readonly")  # Set the entry field back to read-only

def generate_preference_password():
    # Prompt the user to enter password length
    password_length = simpledialog.askinteger("Password Length", "Enter the password length:")

    # Validate password length
    if password_length is None or password_length <= 0:
        messagebox.showerror("Error", "Invalid password length!")
        return

    # Prompt the user to enter additional keywords
    additional_keywords = simpledialog.askstring("Additional Keywords", "Enter additional keywords (comma-separated):")

    if additional_keywords:
        # Split the additional keywords by comma and remove any leading/trailing spaces
        keywords = [keyword.strip() for keyword in additional_keywords.split(",")]

        # Generate a random password with alphanumeric characters
        password_characters = string.ascii_letters + string.digits
        password_length -= len(''.join(keywords))
        password = ''.join(random.choice(password_characters) for _ in range(password_length))

        # Insert the keywords randomly within the password
        password_list = list(password)
        for keyword in keywords:
            random_index = random.randint(0, len(password_list))
            password_list.insert(random_index, keyword)

        # Convert the password list back to a string
        password = ''.join(password_list)
    else:
        # Generate a random password with alphanumeric characters
        password_characters = string.ascii_letters + string.digits
        password = ''.join(random.choice(password_characters) for _ in range(password_length))

    # Insert the generated password into the password entry field
    pm_password_entry.config(state="normal")  # Enable the entry field to modify its content
    pm_password_entry.delete(0, END)
    pm_password_entry.insert(0, password)
    pm_password_entry.config(state="readonly")  # Set the entry field back to read-only

def check_credentials(username, password):
    # Implement your logic to check if the credentials are valid
    c.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = c.fetchone()

    if user:
        stored_password = decrypt_password(user[1])  # Decrypt the stored password
        # Compare the stored password with the entered password
        if stored_password == password:
            return True

    return False


def is_username_available(username):
    # Implement your logic to check if the username is available
    c.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = c.fetchone()

    if user:
        return False

    return True


def store_credentials(username, password, email):
    # Implement your logic to store the username, password, and email
    encrypted_password = encrypt_password(password)  # Encrypt the password
    c.execute("INSERT INTO users (username, password, email) VALUES (?, ?, ?)", (username, encrypted_password, email))
    conn.commit()


def encrypt_password(password):
    # Generate a random IV (Initialization Vector)
    iv = os.urandom(16)  # 16 bytes for AES-256

    # Create a Cipher object using AES-256 CBC mode with the key and IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

    # Create a padder for PKCS7 padding
    padder = padding.PKCS7(128).padder()

    # Apply padding to the password
    padded_password = padder.update(password.encode()) + padder.finalize()

    # Encrypt the padded password
    encryptor = cipher.encryptor()
    encrypted_password = encryptor.update(padded_password) + encryptor.finalize()

    # Combine the IV and encrypted password
    encrypted_data = iv + encrypted_password

    # Return the encrypted data as a Base64-encoded string
    return base64.b64encode(encrypted_data).decode()



def decrypt_password(encrypted_password):
    # Decode the Base64-encoded encrypted data
    encrypted_data = base64.b64decode(encrypted_password)

    # Extract the IV and encrypted password
    iv = encrypted_data[:16]
    encrypted_password = encrypted_data[16:]

    # Create a Cipher object using AES-256 CBC mode with the key and IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

    # Decrypt the encrypted password
    decryptor = cipher.decryptor()
    decrypted_password = decryptor.update(encrypted_password) + decryptor.finalize()

    # Create an unpadder for PKCS7 padding
    unpadder = padding.PKCS7(128).unpadder()

    # Remove the padding from the decrypted password
    unpadded_password = unpadder.update(decrypted_password) + unpadder.finalize()

    # Return the decrypted password as a string
    return unpadded_password.decode()


def save_password():
    if not logged_in:
        messagebox.showerror("Error", "Please log in to access the password manager!")
        return

    website = website_entry.get()
    username = pm_username_entry.get()
    password = pm_password_entry.get()

    if website == "" or username == "" or password == "":
        messagebox.showerror("Error", "Please fill in all fields!")
    else:
        encrypted_password = encrypt_password(password)
        c.execute("INSERT INTO password_manager VALUES (?, ?, ?)", (website, username, encrypted_password))
        conn.commit()
        messagebox.showinfo("Success", "Password saved successfully!")
        clear_entries()



def clear_entries():
    register_username_entry.delete(0, END)
    register_password_entry.delete(0, END)
    register_email_entry.delete(0, END)
    website_entry.delete(0, END)
    pm_username_entry.delete(0, END)
    pm_password_entry.config(state="normal")
    pm_password_entry.delete(0, END)
    pm_password_entry.config(state="readonly")
    
def copy_generate_password():
    password = pm_password_entry.get()
    if password:
        pyperclip.copy(password)
        messagebox.showinfo("Copy Password", "Password copied to clipboard!")





def copy_password():
    selected_item = password_listbox.curselection()
    if selected_item:
        password = password_listbox.get(selected_item)
        password_parts = password.split(" - ")
        if len(password_parts) > 2:
            # Extract only the password part
            password = password_parts[2].split(": ")[1]
            pyperclip.copy(password)
            messagebox.showinfo("Success", "Password copied to clipboard!")
        else:
            messagebox.showerror("Error", "Invalid password format!")
    else:
        messagebox.showerror("Error", "Please select a password to copy!")


password_viewing = False

def show_passwords():
    global password_viewing

    if not logged_in:
        messagebox.showerror("Error", "Please log in to access the password manager!")
        return

    if not password_viewing:
        # Prompt the user to enter the login password
        password_prompt = simpledialog.askstring("Password", "Enter your login password:", show="*")
        if password_prompt is None:
            password_viewing = False
            return

        # Check if the entered password is valid
        if not check_credentials(username_entry.get(), password_prompt):
            messagebox.showerror("Error", "Invalid login password!")
            password_viewing = False
            return

        password_viewing = True

    # Show the passwords if the login password is valid
    c.execute("SELECT * FROM password_manager")
    password_records = c.fetchall()
    password_listbox.delete(0, END)
    for record in password_records:
        website = record[0]
        username = record[1]
        encrypted_password = record[2]
        password = decrypt_password(encrypted_password)
        password_listbox.insert(END, f"Website: {website} - Username: {username} - Password: {password}")

    # Calculate the maximum width needed for the list box
    max_width = max(len(password) for password in password_listbox.get(0, "end"))
    password_listbox.config(width=max_width)

    # Set a timer to clear passwords after a certain time (60 seconds)
    password_listbox.after(60000, clear_passwords)

    


def delete_record():
    # Check if the user is logged in
    if not logged_in:
        messagebox.showerror("Error", "Please log in first!")
        return

    # Prompt the user to enter the current password
    current_password = simpledialog.askstring("Delete Record", "Enter your login password:", show="*")
    if current_password is None:
        return

    # Retrieve the current password from the database
    c.execute("SELECT password FROM users WHERE username = ?", (username_entry.get(),))
    result = c.fetchone()
    if result is None:
        messagebox.showerror("Error", "User not found!")
        return
    stored_password = result[0]

    # Check if the entered password matches the current password
    if not check_credentials(username_entry.get(), current_password):
        messagebox.showerror("Error", "Invalid password!")
        return

    # Retrieve the selected password record from the listbox
    selected_password = password_listbox.get(password_listbox.curselection())

    # Generate a verification code and its expiry timestamp
    verification_code = ''.join(random.choice(string.digits) for _ in range(6))
    verification_code_expiry = time.time() + 300  # Set expiry time to 5 minutes from now

    # Retrieve the user's email
    c.execute("SELECT email FROM users WHERE username = ?", (username_entry.get(),))
    email = c.fetchone()[0]

    # Send the verification code via email
    send_delete_verification_email(email, verification_code)

    # Prompt the user to enter the verification code
    entered_code = simpledialog.askstring("Verification", "Enter the verification code sent to your email:")
    if entered_code is None:
        return

    # Check if the entered code matches the verification code and is within the expiry time
    if entered_code == verification_code and time.time() <= verification_code_expiry:
        # Extract the website name from the selected record
        website = selected_password.split(" - ")[0].split(": ")[1]

        # Delete the selected record from the database
        c.execute("DELETE FROM password_manager WHERE website = ?", (website,))
        conn.commit()

        # Clear the password listbox and show the updated passwords
        clear_passwords()
        show_passwords()

        messagebox.showinfo("Success", "Selected record has been deleted.")
    else:
        messagebox.showerror("Error", "Invalid or expired verification code!")
        return



def change_username():
    # Check if the user is logged in
    if not logged_in:
        messagebox.showerror("Error", "Please log in first!")
        return

    # Prompt the user to enter the new username
    new_username = simpledialog.askstring("Change Username", "Enter a new username:")
    if new_username is None:
        return

    # Retrieve the current email from the database
    c.execute("SELECT email FROM users WHERE username = ?", (username_entry.get(),))
    result = c.fetchone()
    if result is None:
        messagebox.showerror("Error", "User not found!")
        return
    email = result[0]

    # Perform code verification similar to delete_record()
    verification_code = ''.join(random.choice(string.digits) for _ in range(6))
    verification_code_expiry = time.time() + 300  # Set expiry time to 5 minutes from now

    # Send the verification code via email
    send_verification_email(email, verification_code)

    # Prompt the user to enter the verification code
    entered_code = simpledialog.askstring("Verification", "Enter the verification code sent to your email:")
    if entered_code is None:
        return

    # Check if the entered code matches the verification code and is within the expiry time
    if entered_code == verification_code and time.time() <= verification_code_expiry:
        # Update the username in the database
        c.execute("UPDATE users SET username = ? WHERE username = ?", (new_username, username_entry.get()))
        conn.commit()

        # Update the logged-in username
        username_entry.delete(0, END)
        username_entry.insert(0, new_username)

        messagebox.showinfo("Success", "Username changed successfully!")
    else:
        messagebox.showerror("Error", "Invalid or expired verification code!")
        return
    update_user_info(new_username, current_email)

def change_password():
    # Check if the user is logged in
    if not logged_in:
        messagebox.showerror("Error", "Please log in first!")
        return

    # Prompt the user to enter the current password
    current_password = simpledialog.askstring("Change Password", "Enter your current password:", show="*")
    if current_password is None:
        return

    # Retrieve the current password from the database
    c.execute("SELECT password FROM users WHERE username = ?", (username_entry.get(),))
    result = c.fetchone()
    if result is None:
        messagebox.showerror("Error", "User not found!")
        return
    stored_password = result[0]

    # Check if the entered password matches the current password
    if not check_credentials(username_entry.get(), current_password):
        messagebox.showerror("Error", "Invalid password!")
        return

    # Prompt the user to enter a new password
    new_password = simpledialog.askstring("Change Password", "Enter a new password:", show="*")
    if new_password is None:
        return

    # Perform code verification similar to delete_record()
    verification_code = ''.join(random.choice(string.digits) for _ in range(6))
    verification_code_expiry = time.time() + 300  # Set expiry time to 5 minutes from now

    # Retrieve the email from the database
    c.execute("SELECT email FROM users WHERE username = ?", (username_entry.get(),))
    result = c.fetchone()
    if result is None:
        messagebox.showerror("Error", "User not found!")
        return
    email = result[0]

    # Send the verification code via email
    send_verification_email(email, verification_code)

    # Prompt the user to enter the verification code
    entered_code = simpledialog.askstring("Verification", "Enter the verification code sent to your email:")
    if entered_code is None:
        return

    # Check if the entered code matches the verification code and is within the expiry time
    if entered_code == verification_code and time.time() <= verification_code_expiry:
        # Update the password in the database
        encrypted_new_password = encrypt_password(new_password)
        c.execute("UPDATE users SET password = ? WHERE username = ?", (encrypted_new_password, username_entry.get()))
        conn.commit()

        messagebox.showinfo("Success", "Password changed successfully!")
    else:
        messagebox.showerror("Error", "Invalid or expired verification code!")
        return
    update_user_info(username_entry.get(), current_email)

def change_email():
    # Check if the user is logged in
    if not logged_in:
        messagebox.showerror("Error", "Please log in first!")
        return
    # Prompt the user to enter the new email
    new_email = simpledialog.askstring("Change Email", "Enter a new email:")
    if new_email is None:
        return
    # Retrieve the current email from the database
    c.execute("SELECT email FROM users WHERE username = ?", (username_entry.get(),))
    result = c.fetchone()
    if result is None:
        messagebox.showerror("Error", "User not found!")
        return
    email = result[0]
    # Perform code verification similar to delete_record()
    verification_code = ''.join(random.choice(string.digits) for _ in range(6))
    verification_code_expiry = time.time() + 300  # Set expiry time to 5 minutes from now
    # Send the verification code via email
    send_verification_email(email, verification_code)
    # Prompt the user to enter the verification code
    entered_code = simpledialog.askstring("Verification", "Enter the verification code sent to your email:")
    if entered_code is None:
        return
    # Check if the entered code matches the verification code and is within the expiry time
    if entered_code == verification_code and time.time() <= verification_code_expiry:
        # Update the email in the database
        c.execute("UPDATE users SET email = ? WHERE username = ?", (new_email, username_entry.get()))
        conn.commit()

        messagebox.showinfo("Success", "Email changed successfully!")
    else:
        messagebox.showerror("Error", "Invalid or expired verification code!")
        return
    update_user_info(username_entry.get(),current_email)

def toggle_password_visibility():
    if show_password_var.get() == 1:
        pm_password_entry.config(show="")
        root.after(10000, lambda: show_password_var.set(0))
        root.after(10000, lambda: pm_password_entry.config(show="*"))
    else:
        pm_password_entry.config(show="*")

def clear_passwords():
    password_viewing = False
    password_listbox.delete(0, END)
    
    if password_listbox.size() > 0:
        max_width = max(len(password) for password in password_listbox.get(0, "end"))
        password_listbox.config(width=max_width)

    

def switch_to_password_manager():
    saved_passwords_frame.grid_forget()
    settings_frame.grid_forget()  
    password_manager_frame.grid(row=0, column=0, sticky="nsew")  
    password_manager_frame.tkraise()


    
def switch_to_saved_passwords():
    password_manager_frame.grid_forget()
    settings_frame.grid_forget()
    saved_passwords_frame.grid(row=0, column=0, sticky="nsew")
    saved_passwords_frame.tkraise()
    

def switch_to_settings():
    saved_passwords_frame.grid_forget()
    password_manager_frame.grid_forget()  
    settings_frame.grid(row=0, column=0, sticky="nsew")  
    settings_frame.tkraise()

# Creating GUI elements
login_frame = Frame(root)
register_frame = Frame(root)
password_manager_frame = Frame(root)
saved_passwords_frame = Frame(root)
settings_frame = Frame(root)

for frame in (login_frame, register_frame, password_manager_frame,settings_frame,saved_passwords_frame):
    frame.grid(row=0, column=0, sticky="nsew")

root.grid_rowconfigure(0, weight=1)
root.grid_columnconfigure(0, weight=1)

# Login frame
title_label = Label(login_frame, text="PassCrypt Password Manager", font=("Helvetica", 16, "bold"))
title_label.pack(pady=10)

login_label = Label(login_frame, text="Login", font=("Helvetica", 12, "bold"))
login_label.pack()

# Username and Password Entry
entry_frame = Frame(login_frame)
entry_frame.pack(pady=10)

username_frame = Frame(entry_frame)
username_frame.pack(side="left", padx=10)

username_label = Label(username_frame, text="Username:")
username_label.pack(side="left")

username_entry = Entry(username_frame)
username_entry.pack(side="left")

CreateToolTip(username_entry, text='Enter your username')

password_frame = Frame(entry_frame)
password_frame.pack(side="left", padx=10)

password_label = Label(password_frame, text="Password:")
password_label.pack(side="left")

# Show * instead of the actual password
password_entry = Entry(password_frame, show="*")
password_entry.pack(side="left")

CreateToolTip(password_entry, text='Enter your password')

# Login Button
login_button = Button(login_frame, text="Login", command=login)
login_button.pack(pady=20)  # Slightly increased padding

# Register and Forgot Password Buttons
buttons_frame = Frame(login_frame)
buttons_frame.pack()

register_button = Button(buttons_frame, text="Register", command=lambda: switch_frame(register_frame))
register_button.pack(side="left", padx=10)

forgot_password_button = Button(buttons_frame, text="Forgot Password", command=forgot_password)
forgot_password_button.pack(side="left", padx=10, pady=5)  # Added padding


# Bind the <Return> event to the login function
password_entry.bind('<Return>', lambda event: login())
username_entry.delete(0, END)
password_entry.delete(0, END)

login_frame.tkraise()

# Register frame
register_label = Label(register_frame, text="Register", font=("Helvetica", 16, "bold"))
register_label.pack(pady=20)

# Username Entry
register_username_frame = Frame(register_frame)
register_username_frame.pack(pady=10)

register_username_label = Label(register_username_frame, text="Username:")
register_username_label.pack(side="left", padx=10)

register_username_entry = Entry(register_username_frame)
register_username_entry.pack(side="left")

CreateToolTip(register_username_entry, text='Enter your username')

# Password Entry
register_password_frame = Frame(register_frame)
register_password_frame.pack(pady=10)

register_password_label = Label(register_password_frame, text="Password:")
register_password_label.pack(side="left", padx=10)

register_password_entry = Entry(register_password_frame, show="*")
register_password_entry.pack(side="left")

CreateToolTip(register_password_entry, text='Enter your password')

# Email Entry
register_email_frame = Frame(register_frame)
register_email_frame.pack(pady=10)

register_email_label = Label(register_email_frame, text="Email:")
register_email_label.pack(side="left", padx=20)

register_email_entry = Entry(register_email_frame)
register_email_entry.pack(side="left")

CreateToolTip(register_email_entry, text='Enter your email')

# Register Button
register_button = Button(register_frame, text="Register", command=register)
register_button.pack(pady=15)

# Back to Login Button
login_button = Button(register_frame, text="Back to Login", command=lambda: switch_frame(login_frame))
login_button.pack()


# Bind the <Return> event to the register function
register_username_entry.bind('<Return>', lambda event: register())
register_password_entry.bind('<Return>', lambda event: register())
register_email_entry.bind('<Return>', lambda event: register())


# Password Manager frame
manager_label = Label(password_manager_frame, text="PassCrypt Password Manager", font=("Helvetica", 16, "bold"))
manager_label.pack(pady=10)

# Website Entry
website_frame = Frame(password_manager_frame)
website_frame.pack(pady=5)

website_label = Label(website_frame, text="Website Name:")
website_label.pack(side="left", padx=0)

website_entry = Entry(website_frame)
website_entry.pack(side="left")

CreateToolTip(website_entry, text='Enter the website, e.g. google.com')

# Username Entry
pm_username_frame = Frame(password_manager_frame)
pm_username_frame.pack(pady=5)

pm_username_label = Label(pm_username_frame, text="Username:")
pm_username_label.pack(side="left", padx=12)

pm_username_entry = Entry(pm_username_frame)
pm_username_entry.pack(side="left")

CreateToolTip(pm_username_entry, text='Enter your username, e.g. johndoe@example.com or JaneDoe123')

# Password Entry
pm_password_frame = Frame(password_manager_frame)
pm_password_frame.pack(pady=5)

pm_password_label = Label(pm_password_frame, text="Password:")
pm_password_label.pack(side="left", padx=14)

pm_password_entry = Entry(pm_password_frame, show="*", textvariable=password_label, state="readonly")
pm_password_entry.pack(side="left")

show_password_var = IntVar()
show_password_checkbox = Checkbutton(password_manager_frame, text="Show Password", variable=show_password_var, command=toggle_password_visibility)
show_password_checkbox.pack()

# Buttons - First Row
button_frame = Frame(password_manager_frame)
button_frame.pack(pady=10)

copy_password_button = Button(button_frame, text="Copy Password", command=copy_generate_password)
copy_password_button.pack(side="left", padx=5)

# Buttons - Second Row
generate_button_frame = Frame(password_manager_frame)
generate_button_frame.pack()

generate_password_button = Button(generate_button_frame, text="Generate Password", command=generate_password)
generate_password_button.pack(side="left", padx=5)

generate_preference_password_entry = Button(generate_button_frame, text="Generate Preference Password", command=generate_preference_password)
generate_preference_password_entry.pack(side="left", padx=5)

# Buttons - Third Row
save_nav_button_frame = Frame(password_manager_frame)
save_nav_button_frame.pack(pady=10)

save_password_button = Button(save_nav_button_frame, text="Save Password", command=save_password)
save_password_button.pack(side="left", padx=5)

switch_to_saved_passwords_button = Button(save_nav_button_frame, text="Switch to Saved Passwords", command=lambda: switch_frame(saved_passwords_frame))
switch_to_saved_passwords_button.pack(side="left", padx=5)

switch_to_settings_button = Button(save_nav_button_frame, text="Switch to Settings", command=lambda: switch_frame(settings_frame))
switch_to_settings_button.pack(side="left", padx=5)

# Button - Fourth Row
logout_frame = Frame(password_manager_frame)
logout_frame.pack(pady=10)

logout_button = Button(logout_frame, text="Logout", command=logout)
logout_button.pack(side="right", padx=5)  # Move to the fourth row

# Switch to the login frame after logout
logout_button.bind('<ButtonRelease-1>', lambda event: switch_frame(login_frame))

# Saved Passwords frame
manager_label = Label(saved_passwords_frame, text="Saved Password Page", font=("Helvetica", 16, "bold"))
manager_label.pack(pady=10)

# Password Listbox
password_listbox = Listbox(saved_passwords_frame, width=60)
password_listbox.pack(pady=10)

# Buttons Frame
buttons_frame = Frame(saved_passwords_frame)
buttons_frame.pack(pady=15)

# Buttons - First Row
copy_password_button = Button(buttons_frame, text="Copy Password", command=copy_password)
copy_password_button.grid(row=0, column=0, padx=5, pady=10)  # Increased pady

show_passwords_button = Button(buttons_frame, text="Show Passwords", command=show_passwords)
show_passwords_button.grid(row=0, column=1, padx=5, pady=10)  # Increased pady

delete_record_button = Button(buttons_frame, text="Delete Record", command=delete_record)
delete_record_button.grid(row=0, column=2, padx=5, pady=10)  # Increased pady

# Gap between rows
buttons_frame.grid_rowconfigure(1, minsize=20)  # Create a bigger gap
buttons_frame.grid_rowconfigure(2, minsize=20)  # Create the same gap as between the first and second rows

# Buttons - Second Row
clear_passwords_button = Button(buttons_frame, text="Clear Passwords", command=clear_passwords)
clear_passwords_button.grid(row=2, column=0, padx=5)

switch_to_password_manager_button = Button(buttons_frame, text="Switch to Password Manager", command=lambda: switch_frame(password_manager_frame))
switch_to_password_manager_button.grid(row=2, column=1, padx=5)

switch_to_settings_button = Button(buttons_frame, text="Switch to Settings", command=lambda: switch_frame(settings_frame))
switch_to_settings_button.grid(row=2, column=2, padx=5)

# Buttons - Third Row (Logout)
logout_button = Button(buttons_frame, text="Logout", command=logout)
logout_button.grid(row=3, columnspan=3, pady=10)

# Logout Button Binding (Switch to the login frame after logout)
logout_button.bind('<ButtonRelease-1>', lambda event: switch_frame(login_frame))

# Settings frame
manager_label = Label(settings_frame, text="Setting Page", font=("Helvetica", 16, "bold"))
manager_label.pack(pady=10)

# Black frame for user info label
user_info_frame = Frame(settings_frame, bg="black")
user_info_frame.pack()

# Label to Display Current Logged In User Info
user_info_label = Label(user_info_frame, text="", font=("Helvetica", 14), bg="dark grey", fg="blue")
user_info_label.pack()

# Buttons Frame - First Row
button_frame_1 = Frame(settings_frame)
button_frame_1.pack(pady=10)

change_username_button = Button(button_frame_1, text="Change Username", command=change_username)
change_username_button.pack(side="left", padx=5)

change_password_button = Button(button_frame_1, text="Change Password", command=change_password)
change_password_button.pack(side="left", padx=5)

change_email_button = Button(button_frame_1, text="Change Email", command=change_email)
change_email_button.pack(side="left", padx=5)

# Buttons Frame - Second Row
button_frame_2 = Frame(settings_frame)
button_frame_2.pack(pady=10)

switch_to_password_manager_button = Button(button_frame_2, text="Switch to Password Manager", command=lambda: switch_frame(password_manager_frame))
switch_to_password_manager_button.pack(side="left", padx=5)

switch_to_saved_passwords_button = Button(button_frame_2, text="Switch to Saved Passwords", command=lambda: switch_frame(saved_passwords_frame))
switch_to_saved_passwords_button.pack(side="left", padx=5)

# Logout Button - Third Row
logout_button = Button(settings_frame, text="Logout", command=logout)
logout_button.pack(pady=10)



# Bind the <Return> event to the save_password function
website_entry.bind('<Return>', lambda event: save_password())
pm_username_entry.bind('<Return>', lambda event: save_password())
pm_password_entry.bind('<Return>', lambda event: save_password())


# Configure grid weights for the password manager frame
password_manager_frame.grid_rowconfigure(10, weight=1)
password_manager_frame.grid_columnconfigure(0, weight=1)

# Start the GUI
root.mainloop()

