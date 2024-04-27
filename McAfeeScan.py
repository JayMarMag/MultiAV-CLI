import subprocess
import argparse
import os
import sys
import json
import hashlib
import sqlite3
from prettytable import PrettyTable
import ntpath

# Define the argument parser
parser = argparse.ArgumentParser(description='Scan a directory using multiple antivirus software and update an existing SQLite3 database.')
parser.add_argument('directory', metavar='directory', type=str, help='The directory to scan')
args = parser.parse_args()

# Get input directory from command line argument
input_dir = args.directory

# Change working directory to McAfee/
os.chdir('McAfee')

# Run McAfee scan on the input directory
#command = f'scan.exe /HIDEMD5 /FAM /SECURE /PROGRAM /SUB /SHOWCOMP /SHOWENCRYPTED /JSONPATH=..\Logs\MCreport.json {input_dir}'
#subprocess.run(command, shell=True, check=False)

# Load the JSON log from file
with open('..\Logs\MCreport.json', 'r') as file:
    log_data = json.load(file)

# Extract the necessary data for infected objects
infected_objects = []
for obj in log_data['Scan']['objects']:
    if obj['report']['status'] == 'infected':
        filename = ntpath.basename(obj['object']['name'])
        malware_name = obj['report']['virus-name']
        malware_type = obj['report']['detection-type']
        
        # Get the full file path
        file_path = os.path.join(input_dir, filename)
        
        if os.path.exists(file_path):
            # Calculate MD5 hash if the file exists
            with open(file_path, 'rb') as file:
                md5_hash = hashlib.md5(file.read()).hexdigest()
        else:
            # Set MD5 hash as None if the file doesn't exist
            md5_hash = None
        
        infected_objects.append({
            'filename': filename,
            'malware_name': malware_name,
            'malware_type': malware_type,
            'md5_hash': md5_hash
        })

# Open the database connection
db_path = '..\db\MalwareScan.db'
conn = sqlite3.connect(db_path)
cursor = conn.cursor()

# Check and update the database
for infected_object in infected_objects:
    filename = infected_object['filename']
    md5_hash = infected_object['md5_hash']
    malware_name = infected_object['malware_name']
    
    if md5_hash is not None:
        # Check if MD5 hash exists in the database
        cursor.execute("SELECT MD5 FROM MalwareScan WHERE MD5=?", (md5_hash,))
        existing_md5 = cursor.fetchone()
        
        if existing_md5:
            # Update the existing row with McAfee malware name
            cursor.execute("UPDATE MalwareScan SET McAfee=?, Filename=? WHERE MD5=?", (malware_name, filename, md5_hash))
        else:
            # Insert a new row into the database
            cursor.execute("INSERT INTO MalwareScan (MD5, McAfee, Filename) VALUES (?, ?, ?)", (md5_hash, malware_name, filename))

# Commit the changes and close the connection
conn.commit()
conn.close()

# Print the extracted data
if infected_objects:
    table = PrettyTable()
    table.align = "l"
    table.field_names = ['Filename', 'Malware Name', 'Malware Type', 'MD5 Hash']
    for infected_object in infected_objects:
        table.add_row([infected_object['filename'], infected_object['malware_name'], infected_object['malware_type'], infected_object['md5_hash']])
    print(table)
else:
    print("No infected objects found.")
