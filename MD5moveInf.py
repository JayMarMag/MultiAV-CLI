import os
import sys
import hashlib
import sqlite3
import shutil

# Function to calculate MD5 hash of a file
def calculate_md5(file_path):
    with open(file_path, "rb") as f:
        file_hash = hashlib.md5()
        while chunk := f.read(4096):
            file_hash.update(chunk)
    return file_hash.hexdigest()

# Connect to SQLite database
db_path = r'c:\Apps\AV\DB\MalwareScan.db'
conn = sqlite3.connect(db_path)
cursor = conn.cursor()

# Create table if it doesn't exist
cursor.execute('''CREATE TABLE IF NOT EXISTS MalwareScan (
                    MD5 TEXT PRIMARY KEY
                  )''')

# Function to check if MD5 exists in database
def is_md5_in_db(md5):
    cursor.execute("SELECT MD5 FROM MalwareScan WHERE MD5=?", (md5,))
    result = cursor.fetchone()
    return result is not None

# Function to move file to infected folder
def move_to_infected(file_path):
    infected_folder = r'd:\Malware\Infected'
    filename = os.path.basename(file_path)
    destination = os.path.join(infected_folder, filename)
    shutil.move(file_path, destination)

# Check command line arguments
if len(sys.argv) != 2:
    print("Usage: python script.py <folder_path>")
    sys.exit(1)

folder_path = sys.argv[1]

# Loop through files in folder
for root, dirs, files in os.walk(folder_path):
    for file in files:
        file_path = os.path.join(root, file)
        if os.path.isfile(file_path):
            md5 = calculate_md5(file_path)
            if is_md5_in_db(md5):
                print(f"File '{file}' is infected. Moving to infected folder...")
                move_to_infected(file_path)
            else:
                print(f"File '{file}' is clean. No action needed.")

# Close database connection
conn.close()
