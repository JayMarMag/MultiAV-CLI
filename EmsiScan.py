import subprocess
import argparse
import os
import hashlib
import sys
from prettytable import PrettyTable
import sqlite3


# Define the argument parser
parser = argparse.ArgumentParser(description='Scan a directory using multiple antivirus software and save the results to a SQLite3 database.')
parser.add_argument('directory', metavar='directory', type=str, help='The directory to scan')
args = parser.parse_args()

# get input directory from command line argument
input_dir = sys.argv[1]

# run Emsisoft scan on the input directory
command = f'EEK\\bin64\\a2cmd.exe /a /am /cloud=1 /pup /la=..\..\Logs\EEK-Report.log "{input_dir}"'
subprocess.run(command, shell=True, check=False)

# Parse the log contents to get the Filename and Malware name
table = PrettyTable(['Filename', 'MD5 Hash', 'Malware Name'])
table.align = "l"

# Open the log file from Emsisoft
with open('Logs/EEK-Report.log') as f:
    data = f.read()

# extract the data from the log
rows = []
for line in data.splitlines():
    if "detected:" in line:
        parts = line.split("detected:")
        filepath = parts[0].strip()
        malware_name = parts[1].split("(")[0].strip()
        filename = os.path.basename(filepath)
        abs_path = os.path.join(input_dir, filepath)
        if os.path.exists(abs_path):
            md5_hash = hashlib.md5(open(abs_path, 'rb').read()).hexdigest()
            rows.append([
                filepath,
                md5_hash,
                malware_name
            ])
        else:
            print(f"File not found: {abs_path}")

# create the table and add the rows
table = PrettyTable()
table.field_names = ['Filename', 'MD5', 'Malware name']
table.align = "l"


# add data to the database
conn = sqlite3.connect('db/MalwareScan.db')
c = conn.cursor()
for row in rows:
    filepath, md5_hash, malware_name = row
    # check if md5 hash already exists in database
    c.execute('SELECT MD5 FROM MalwareScan WHERE MD5 = ?', (md5_hash,))
    result = c.fetchone()
    if result:
        # update the Emsisoft column with the malware name
        c.execute('UPDATE MalwareScan SET Emsisoft = ? WHERE MD5 = ?', (malware_name, md5_hash))
    else:
        # insert a new row in the database
        c.execute('INSERT INTO MalwareScan (Filename, MD5, Emsisoft) VALUES (?, ?, ?)', (filename, md5_hash, malware_name))
conn.commit()
conn.close()

# print the table
for row in rows:
    table.add_row(row)
print(table)
