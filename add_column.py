import sqlite3

conn = sqlite3.connect("database.db")
cursor = conn.cursor()

# Add the password column if it doesn't exist
try:
    cursor.execute("ALTER TABLE therapist ADD COLUMN password TEXT;")
    print("Password column added successfully!")
except sqlite3.OperationalError as e:
    print("Column probably already exists:", e)

conn.commit()
conn.close()
