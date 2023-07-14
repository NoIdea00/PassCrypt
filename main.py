import base64
import os
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
root.title("Password Manager")
root.geometry("500x500")
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


# Creating functions

def switch_frame(frame):
    clear_entries()
    frame.tkraise()
    print ("test successful")

def clear_entries():
    register_username_entry.delete(0, END)
    register_password_entry.delete(0, END)
    register_email_entry.delete(0, END)
    username_entry.delete(0, END)
    password_entry.delete(0, END)
    website_entry.delete(0, END)
    pm_username_entry.delete(0, END)
    pm_password_entry.delete(0, END)


def register():
    # Retrieve username, password, and email from the user
    username = register_username_entry.get()
    password = register_password_entry.get()
    email = register_email_entry.get()

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
           "Your registration was successful.\n\nBest regards,\nThe Password Manager Team"
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
    msg["Subject"] = "Verification Code"
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
    msg["Subject"] = "Verification Code"
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
    msg["Subject"] = "Verification Code"
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


def send_files(email, filenames):
    

    # Create a message object
    msg = EmailMessage()
    
    # Set the subject and recipient
    msg["Subject"] = "Verification Code"
    msg["To"] = email
    
    # Compose the email body
    body = f"Attached is the db and key file"
    msg.set_content(body)

    for file in filenames:
        with open(file, "rb") as f:
            file_data = f.read()
            file_name = f.name

        msg.add_attachment(file_data, maintype="application", subtype="octet-stream", filename=file_name)
    
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


def login():
    # Retrieve username and password from the user
    username = username_entry.get()
    password = password_entry.get()

    # Check if the credentials are valid
    if check_credentials(username, password):
        # Generate a verification code and its expiry timestamp
        verification_code = ''.join(random.choice(string.digits) for _ in range(6))
        verification_code_expiry = time.time() + 300  # Set expiry time to 5 minutes from now
        
        # Retrieve the user's email
        c.execute("SELECT email FROM users WHERE username = ?", (username,))
        email = c.fetchone()[0]
        
        # Send the verification code via email
        send_login_verification_email(email, verification_code)
        
        # Prompt the user to enter the verification code
        entered_code = simpledialog.askstring("Verification", "Enter the verification code sent to your email:")
        
        # Check the validity of the verification code
        if entered_code == verification_code and time.time() <= verification_code_expiry:
            global logged_in
            logged_in = True
            
            switch_frame(password_manager_frame)
            clear_entries()
        else:
            messagebox.showerror("Error", "Invalid or expired verification code!")
    else:
        messagebox.showerror("Error", "Invalid credentials!")


def logout():
    global logged_in
    logged_in = False
    # retrieve user email address
    c.execute("SELECT email FROM users WHERE username = ?", (username_entry.get(),))
    email = c.fetchone()[0]

    # send db file to email
    prompt_send_db = simpledialog.askstring("Send DB", "Send db file: yes/no")
    if prompt_send_db == "yes":
        send_files(email, [database_path, key_file_path])
    else:
        pass
    switch_frame(login_frame)
    clear_entries()
    

def generate_password():
    # Generate a random password with a combination of letters, digits, and special characters
    password_length = 16  # Set the desired length of the password
    password_characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(password_characters) for _ in range(password_length))


    # Insert the generated password into the password entry field
    pm_password_entry.delete(0, END)
    pm_password_entry.insert(0, password)


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

        # Generate a random password with alphanumeric characters and symbols
        password_characters = string.ascii_letters + string.digits + string.punctuation
        password = ''.join(random.choice(password_characters) for _ in range(password_length))

        # Calculate the remaining length after inserting the keyword string
        remaining_length = password_length - len(keywords)

        if remaining_length <= 0:
            messagebox.showerror("Error", "Password length is too short for the additional keywords!")
            return

        # Create a list to hold the password characters
        password_list = list(password)

        # Insert the keywords randomly within the password
        for keyword in keywords:
            random_index = random.randint(0, remaining_length)
            password_list.insert(random_index, keyword)
            remaining_length -= 1

        # Convert the password list back to a string
        password = ''.join(password_list)
    else:
        # Generate a random password with alphanumeric characters and symbols
        password_characters = string.ascii_letters + string.digits + string.punctuation
        password = ''.join(random.choice(password_characters) for _ in range(password_length))

    # Insert the generated password into the password entry field
    pm_password_entry.delete(0, END)
    pm_password_entry.insert(0, password)





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
    website_entry.delete(0, END)
    pm_username_entry.delete(0, END)
    pm_password_entry.delete(0, END)


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


def show_passwords():
    if not logged_in:
        messagebox.showerror("Error", "Please log in to access the password manager!")
        return

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
    password_listbox.after(60000, clear_passwords)


def delete_record():
    # Check if the user is logged in
    if not logged_in:
        messagebox.showerror("Error", "Please log in first!")
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




def clear_passwords():
    password_viewing = False
    password_listbox.delete(0, END)

def switch_to_password_manager():
    saved_passwords_frame.grid_forget()  
    password_manager_frame.grid(row=0, column=0, sticky="nsew")  
    password_manager_frame.tkraise()  

    
def switch_to_saved_passwords():
    password_manager_frame.grid_forget()  
    saved_passwords_frame.grid(row=0, column=0, sticky="nsew")  
    saved_passwords_frame.tkraise()  

def switch_to_settings():
    password_manager_frame.grid_forget()  
    settings_frame.grid(row=0, column=0, sticky="nsew")  
    settings_frame.tkraise()

# Creating GUI elements
login_frame = Frame(root)
register_frame = Frame(root)
password_manager_frame = Frame(root)
saved_passwords_frame = Frame(root)
settings_frame = Frame(root)

for frame in (login_frame, register_frame, password_manager_frame,settings_frame):
    frame.grid(row=0, column=0, sticky="nsew")

root.grid_rowconfigure(0, weight=1)
root.grid_columnconfigure(0, weight=1)

# Login frame
login_label = Label(login_frame, text="Login")
login_label.pack()

username_label = Label(login_frame, text="Username:")
username_label.pack()

username_entry = Entry(login_frame)
username_entry.pack()

CreateToolTip(username_entry, text = 'Enter your username')

password_label = Label(login_frame, text="Password:")
password_label.pack()

# Show * instead of the actual password
password_entry = Entry(login_frame, show="*")
password_entry.pack()

CreateToolTip(password_entry, text = 'Enter your password')

login_button = Button(login_frame, text="Login", command=login)
login_button.pack()

register_button = Button(login_frame, text="Register", command=lambda: switch_frame(register_frame))
register_button.pack()

# Bind the <Return> event to the login function
password_entry.bind('<Return>', lambda event: login())

login_frame.tkraise()

# Register frame
register_label = Label(register_frame, text="Register")
register_label.pack()

register_username_label = Label(register_frame, text="Username:")
register_username_label.pack()

register_username_entry = Entry(register_frame)
register_username_entry.pack()

CreateToolTip(register_username_entry, text = 'Enter your username')

register_password_label = Label(register_frame, text="Password:")
register_password_label.pack()

register_password_entry = Entry(register_frame, show="*")
register_password_entry.pack()

CreateToolTip(register_password_entry, text = 'Enter your password')

register_email_label = Label(register_frame, text="Email:")
register_email_label.pack()

register_email_entry = Entry(register_frame)
register_email_entry.pack()

CreateToolTip(register_email_entry, text = 'Enter your email')

register_button = Button(register_frame, text="Register", command=register)
register_button.pack()

login_button = Button(register_frame, text="Back to Login", command=lambda: switch_frame(login_frame))
login_button.pack()

# Bind the <Return> event to the register function
register_username_entry.bind('<Return>', lambda event: register())
register_password_entry.bind('<Return>', lambda event: register())
register_email_entry.bind('<Return>', lambda event: register())


# Password Manager frame
manager_label = Label(password_manager_frame, text="Password Manager")
manager_label.pack()

website_label = Label(password_manager_frame, text="Website:")
website_label.pack()

website_entry = Entry(password_manager_frame)
website_entry.pack()

CreateToolTip(website_entry, text = 'Enter the website, e.g. google.com')

pm_username_label = Label(password_manager_frame, text="Username:")
pm_username_label.pack()

pm_username_entry = Entry(password_manager_frame)
pm_username_entry.pack()

CreateToolTip(pm_username_entry, text = 'Enter your username, e.g. johndoe@example.com or JaneDoe123')

pm_password_label = Label(password_manager_frame, text="Password:")
pm_password_label.pack()

pm_password_entry = Entry(password_manager_frame, show="*")
pm_password_entry.pack()


generate_password_button = Button(password_manager_frame, text="Generate Password", command=generate_password)
generate_password_button.pack()

generate_preference_password_entry = Button(password_manager_frame, text="Generate Preference Password", command=generate_preference_password)
generate_preference_password_entry.pack()

save_password_button = Button(password_manager_frame, text="Save Password", command=save_password)
save_password_button.pack()

switch_to_saved_passwords_button = Button(password_manager_frame, text="Switch to Saved Passwords", command=lambda: switch_frame(saved_passwords_frame))
switch_to_saved_passwords_button.pack()

switch_to_settings_button = Button(password_manager_frame, text="Switch to Settings", command=lambda: switch_frame(settings_frame))
switch_to_settings_button.pack()

logout_button = Button(password_manager_frame, text="Logout", command=logout)
logout_button.pack()

# Switch to the login frame after logout
logout_button.bind('<ButtonRelease-1>', lambda event: switch_frame(login_frame))

# Saved Passwords frame
password_listbox = Listbox(saved_passwords_frame, width=60)
password_listbox.pack()

copy_password_button = Button(saved_passwords_frame, text="Copy Password", command=copy_password)
copy_password_button.pack()

show_passwords_button = Button(saved_passwords_frame, text="Show Passwords", command=show_passwords)
show_passwords_button.pack()

delete_record_button = Button(saved_passwords_frame, text="Delete Record", command=delete_record)
delete_record_button.pack()

clear_passwords_button = Button(saved_passwords_frame, text="Clear Passwords", command=clear_passwords)
clear_passwords_button.pack()

switch_to_password_manager_button = Button(saved_passwords_frame, text="Switch to Password Manager", command=lambda: switch_frame(password_manager_frame))
switch_to_password_manager_button.pack()

# switch to setting frame
change_username_button = Button(settings_frame, text="Change Username", command=change_username)
change_username_button.pack()

change_password_button = Button(settings_frame, text="Change Password", command=change_password)
change_password_button.pack()

change_email_button = Button(settings_frame, text="Change Email", command=change_email)
change_email_button.pack()

switch_to_password_manager_button = Button(settings_frame, text="Switch to Password Manager", command=lambda: switch_frame(password_manager_frame))
switch_to_password_manager_button.pack()

switch_to_saved_passwords_button = Button(settings_frame, text="Switch to Saved Passwords", command=lambda: switch_frame(saved_passwords_frame))
switch_to_saved_passwords_button.pack()

logout_button = Button(settings_frame, text="Logout", command=logout)
logout_button.pack()


# Bind the <Return> event to the save_password function
website_entry.bind('<Return>', lambda event: save_password())
pm_username_entry.bind('<Return>', lambda event: save_password())
pm_password_entry.bind('<Return>', lambda event: save_password())


# Configure grid weights for the password manager frame
password_manager_frame.grid_rowconfigure(10, weight=1)
password_manager_frame.grid_columnconfigure(0, weight=1)

# Start the GUI
root.mainloop()

## commit for Debricked
