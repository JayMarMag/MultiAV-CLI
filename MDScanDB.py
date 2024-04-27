import subprocess
import sys
import re
import hashlib
from prettytable import PrettyTable
import os
import sqlite3

def calculate_md5(file_path):
    # Calculate MD5 hash of the file
    md5_hash = hashlib.md5()
    with open(file_path, "rb") as f:
        # Read the file in chunks to handle large files
        for chunk in iter(lambda: f.read(4096), b""):
            md5_hash.update(chunk)
    return md5_hash.hexdigest()

def scan_folder_with_defender(folder_path):
    # Define the command and arguments for scanning
    mpcmdrun_exe = "c:\\Apps\\AV\\MSDefender\\MpCmdRun.exe"
    args = ["-Scan", "-ScanType", "3", "-File", folder_path, "-DisableRemediation"]

    # Run the MS Defender command line tool to scan the folder and save the output to a file
    with open("Logs/MSDefender.log", "w") as output_file:
        result = subprocess.run([mpcmdrun_exe] + args, capture_output=True, text=True)
        output_file.write(result.stdout)

    # Get all files in the folder and calculate their MD5 hashes
    file_hashes = {}
    for root, dirs, files in os.walk(folder_path):
        for filename in files:
            file_path = os.path.join(root, filename)
            file_hashes[file_path] = calculate_md5(file_path)

    # Parse the output file to get the filename and threat name
    threats = []
    with open("Logs/MSDefender.log", "r") as input_file:
        threat_info = None
        for line in input_file:
            if "Threat" in line:
                threat_info = re.search(r"Threat\s+:\s+(.*)", line)
            elif "file" in line and threat_info:
                filename_match = re.search(r"file\s+:\s+(.*)", line)
                if filename_match:
                    # Extract only the filename without the path
                    filename = filename_match.group(1).split("\\")[-1].strip()
                    # Remove anything after "->" in the filename
                    filename = re.sub(r'\s*->.*$', '', filename)
                    file_path = filename_match.group(1).strip()
                    # Get the MD5 hash for the file
                    md5_hash = file_hashes.get(file_path)
                    if md5_hash:  # If file is in the list of scanned files
                        threats.append((filename, md5_hash, threat_info.group(1)))
    return threats

def update_or_insert_to_db(threats):
    # Connect to the SQLite database
    conn = sqlite3.connect("db/MalwareScan.db")
    cursor = conn.cursor()

    for filename, md5_hash, threat_name in threats:
        # Check if MD5 hash exists in the database
        cursor.execute("SELECT * FROM MalwareScan WHERE MD5 = ?", (md5_hash,))
        existing_entry = cursor.fetchone()

        if existing_entry:
            # If MD5 exists, update the threat name
            cursor.execute("UPDATE MalwareScan SET MS_Defender = ? WHERE MD5 = ?", (threat_name, md5_hash))
        else:
            # If MD5 doesn't exist, insert new entry
            cursor.execute("INSERT INTO MalwareScan (Filename, MD5, MS_Defender) VALUES (?, ?, ?)", (filename, md5_hash, threat_name))

    # Commit changes and close connection
    conn.commit()
    conn.close()

# Check if folder path is provided as a command-line argument
if len(sys.argv) != 2:
    print("Usage: python scan_folder.py <folder_path>")
    sys.exit(1)

# Get the folder path from the command-line argument
folder_path = sys.argv[1]

# Call the function to scan the folder and print the results
threats = scan_folder_with_defender(folder_path)

# Update or insert threats into the database
update_or_insert_to_db(threats)

# Create a PrettyTable object
table = PrettyTable()
table.field_names = ["Filename", "MD5 Hash", "Threat Name"]

# Set alignment to left
table.align["Filename"] = "l"
table.align["MD5 Hash"] = "l"
table.align["Threat Name"] = "l"

# Add data to the table
for filename, md5_hash, threat_name in threats:
    table.add_row([filename, md5_hash, threat_name])

# Print the table
print(table)
