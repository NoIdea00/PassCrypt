from tkinter import *
from tkinter import messagebox
from tkinter import simpledialog
import sqlite3
from cryptography.fernet import Fernet
import pyperclip
import random
import string

# Creating window
root = Tk()
root.title("Password Manager")
root.geometry("500x500")
root.resizable(False, False)
root.config(bg="grey")

# Creating database
conn = sqlite3.connect("password_manager.db")
c = conn.cursor()

# Creating tables
c.execute("""CREATE TABLE IF NOT EXISTS users(
            username TEXT,
            password TEXT
            )""")

c.execute("""CREATE TABLE IF NOT EXISTS password_manager(
            website TEXT,
            username TEXT,
            password TEXT
            )""")

conn.commit()

# Creating key
key_file_path = "key.key"
key = None


def generate_key():
    return Fernet.generate_key()


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

f = Fernet(key)


# Global variables
logged_in = False
password_visibility = False
password_viewing = False


# Creating functions

def switch_frame(frame):
    frame.tkraise()


def register():
    # Implement your register logic here
    # Retrieve username and password from the user
    username = register_username_entry.get()
    password = register_password_entry.get()

    # Check if the username is available
    if is_username_available(username):
        # Store the credentials
        store_credentials(username, password)
        messagebox.showinfo("Success", "User registered successfully!")
    else:
        messagebox.showerror("Error", "Username is not available! Register another username.")


def login():
    # Implement your login logic here
    # Retrieve username and password from the user
    username = username_entry.get()
    password = password_entry.get()

    # Check if the credentials are valid
    if check_credentials(username, password):
        global logged_in
        logged_in = True

        switch_frame(password_manager_frame)
        clear_entries()
    else:
        messagebox.showerror("Error", "Invalid credentials!")


def logout():
    global logged_in
    logged_in = False
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


def store_credentials(username, password):
    # Implement your logic to store the username and password
    encrypted_password = encrypt_password(password)  # Encrypt the password
    c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, encrypted_password))
    conn.commit()


def encrypt_password(password):
    # Encrypt the password using Fernet encryption
    return f.encrypt(password.encode()).decode()


def decrypt_password(encrypted_password):
    # Decrypt the password using Fernet encryption
    return f.decrypt(encrypted_password.encode()).decode()


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

    global password_viewing
    if password_viewing:
        messagebox.showinfo("Info", "You are already viewing the passwords!")
        return

    password_viewing = True

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
    
    if not logged_in:
        messagebox.showerror("Error", "Please log in to access the password manager!")
        return

    selected_item = password_listbox.curselection()
    if not selected_item:
        messagebox.showwarning("Warning", "Please select a record to delete!")
        return
    
    messagebox.showwarning("Warning", "This action cannot be undone!")
    
    # Prompt the user to enter the login password
    password_prompt = simpledialog.askstring("Password", "Enter your login password:", show="*")
    if password_prompt is None:
        return

    # Check if the entered password is valid
    if not check_credentials(username_entry.get(), password_prompt):
        messagebox.showerror("Error", "Invalid login password!")
        return


    password = password_listbox.get(selected_item)
    password_parts = password.split(" - ")
    if len(password_parts) > 2:
        website = password_parts[0].split(": ")[1]
        username = password_parts[1].split(": ")[1]
        c.execute("DELETE FROM password_manager WHERE website = ? AND username = ?", (website, username))
        conn.commit()
        password_listbox.delete(selected_item)
        messagebox.showinfo("Success", "Record deleted successfully!")
    else:
        messagebox.showerror("Error", "Invalid password format!")


def clear_passwords():
    password_viewing = False
    password_listbox.delete(0, END)


# Creating GUI elements
login_frame = Frame(root)
register_frame = Frame(root)
password_manager_frame = Frame(root)

for frame in (login_frame, register_frame, password_manager_frame):
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

password_label = Label(login_frame, text="Password:")
password_label.pack()

# Show * instead of the actual password
password_entry = Entry(login_frame, show="*")
password_entry.pack()

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

register_password_label = Label(register_frame, text="Password:")
register_password_label.pack()

# Set the 'show' attribute to '*'
register_password_entry = Entry(register_frame, show="*")
register_password_entry.pack()

register_button = Button(register_frame, text="Register", command=register)
register_button.pack()

login_button = Button(register_frame, text="Back to Login", command=lambda: switch_frame(login_frame))
login_button.pack()

# Bind the <Return> event to the register function
register_username_entry.bind('<Return>', lambda event: register())
register_password_entry.bind('<Return>', lambda event: register())


# Password Manager frame
manager_label = Label(password_manager_frame, text="Password Manager")
manager_label.pack()

website_label = Label(password_manager_frame, text="Website:")
website_label.pack()

website_entry = Entry(password_manager_frame)
website_entry.pack()

pm_username_label = Label(password_manager_frame, text="Username:")
pm_username_label.pack()

pm_username_entry = Entry(password_manager_frame)
pm_username_entry.pack()

pm_password_label = Label(password_manager_frame, text="Password:")
pm_password_label.pack()

# Set the 'show' attribute to '*'
pm_password_entry = Entry(password_manager_frame)
pm_password_entry.pack()

generate_button = Button(password_manager_frame, text="Generate Password", command=generate_password)
generate_button.pack()


save_button = Button(password_manager_frame, text="Save", command=save_password)
save_button.pack()

password_listbox = Listbox(password_manager_frame, width=60)
password_listbox.pack()

copy_button = Button(password_manager_frame, text="Copy Password", command=copy_password)
copy_button.pack()

show_passwords_button = Button(password_manager_frame, text="Show Passwords", command=show_passwords)
show_passwords_button.pack()

delete_button = Button(password_manager_frame, text="Delete Record", command=delete_record)
delete_button.pack()

logout_button = Button(password_manager_frame, text="Logout", command=logout)
logout_button.pack()

root.mainloop()

# Close the database connection when the application exits
conn.close()