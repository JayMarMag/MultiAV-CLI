import sys
import os
import subprocess
import hashlib
import sqlite3
from prettytable import PrettyTable

def scan_directory(directory):
    # Assemble the command with the provided directory
    command = ["DrWebCL\drwebwcl.exe", "/ha", directory]

    try:
        # Execute the command and capture the output
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        print(result.stdout)  # Print the standard output (if needed)
        print(result.stderr)  # Print the error output (if needed)
    except subprocess.SubprocessError as e:
        print(f"Error executing Dr.Web command: {e}")
        sys.exit(1)

def calculate_md5(file_path):
    if not os.path.exists(file_path):
        return "N/A"

    with open(file_path, "rb") as file:
        md5_hash = hashlib.md5()
        while True:
            chunk = file.read(4096)
            if not chunk:
                break
            md5_hash.update(chunk)
    return md5_hash.hexdigest()

def remove_loading_lines(log_path):
    with open(log_path, "r", encoding="utf-8", errors='ignore') as file:
        lines = file.readlines()

    # Remove lines containing "Loading"
    lines = [line for line in lines if "Loading" not in line]

    with open(log_path, "w", encoding="utf-8") as file:
        file.writelines(lines)

def parse_log(file_path):
    with open(file_path, "r", encoding="utf-8") as file:
        lines = file.readlines()

    # Extract filename and malware name
    malware_entries = []
    malware_name = None
    for line in lines:
        if "infected with" in line:
            parts = line.split("infected with", 1)
            filename = parts[0].strip()
            malware_name = parts[1].strip()
            malware_entries.append((filename, malware_name))
        elif "is adware program" in line:
            parts = line.split("is adware program", 1)
            filename = parts[0].strip()
            malware_name = parts[1].strip()
            malware_entries.append((filename, malware_name))
        elif "is riskware program" in line:
            parts = line.split("is riskware program", 1)
            filename = parts[0].strip()
            malware_name = parts[1].strip()
            malware_entries.append((filename, malware_name))
        elif "is hacktool program" in line:
            parts = line.split("is hacktool program", 1)
            filename = parts[0].strip()
            malware_name = parts[1].strip()
            malware_entries.append((filename, malware_name))
        elif " - archive contains infected objects" in line:
            # Check if a malware name was previously seen
            if malware_name:
                filename = line.replace(" - archive contains infected objects", "").strip()
                malware_entries.append((filename, malware_name))

    return malware_entries

def update_db_malware_name(db_path, md5_hash, filename, malware_name):
    filename = os.path.basename(filename)
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM MalwareScan WHERE MD5 = ?", (md5_hash,))
    existing_entry = cursor.fetchone()
    if existing_entry:
        cursor.execute("UPDATE MalwareScan SET DrWeb = ? WHERE MD5 = ?", (malware_name, md5_hash))
    else:
        cursor.execute("INSERT INTO MalwareScan (MD5, Filename, DrWeb) VALUES (?, ?, ?)", (md5_hash, filename, malware_name))
    conn.commit()
    conn.close()



if __name__ == "__main__":
    # Check if the correct number of arguments is provided
    if len(sys.argv) != 2:
        print("Usage: python script_name.py InputDir")
        sys.exit(1)

    # Get the directory path from the command-line argument
    input_dir = sys.argv[1]

    # Perform the scanning operation
    scan_directory(input_dir)

    # Remove lines containing "Loading" from the log file
    log_path = "Logs\\DrWeb.log"
    remove_loading_lines(log_path)

    # Parse the log and extract filename and malware name
    malware_entries = parse_log(log_path)

    # Calculate MD5 hash for each detected file
    for i, (filename, malware_name) in enumerate(malware_entries):
        if "archive contains infected objects" not in filename:
            file_path = os.path.join(input_dir, filename)
            md5_hash = calculate_md5(file_path)
            if md5_hash != "N/A":
                malware_entries[i] = (filename, malware_name, md5_hash)
                db_path = "db/MalwareScan.db"

                # Update the database using prepared statements to prevent SQL injection
                conn = sqlite3.connect(db_path)
                cursor = conn.cursor()
                cursor.execute("BEGIN TRANSACTION")
                update_db_malware_name(db_path, md5_hash, filename, malware_name)
                cursor.execute("END TRANSACTION")
                conn.commit()
                conn.close()

    # Print the extracted information in a pretty table
    table = PrettyTable()
    table.field_names = ["Filename", "Malware Name", "MD5 Hash"]
    table.align = "l"
    for entry in malware_entries:
        if len(entry) == 3:
            table.add_row(entry)

    print("\nDetected Malware:")
    print(table)
