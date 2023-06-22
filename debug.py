import sqlite3


conn = sqlite3.connect("password_manager.db")
c = conn.cursor()

c.execute("SELECT * FROM users")
print(c.fetchall())