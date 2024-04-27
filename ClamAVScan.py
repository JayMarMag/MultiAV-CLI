import subprocess
import argparse
import os
import hashlib
import sys
from prettytable import PrettyTable
import sqlite3


# Function to calculate the MD5 hash of a file
def calculate_md5(file_path):
    hash_md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest().lower()


# Define the argument parser
parser = argparse.ArgumentParser(description='Scan a directory using multiple antivirus software and save the results to a SQLite3 database.')
parser.add_argument('directory', metavar='directory', type=str, help='The directory to scan')
args = parser.parse_args()

# get input directory from command line argument
input_dir = sys.argv[1]

# change working directory to ClamAV/
os.chdir('clamav')

# run ClamAV scan on the input directory
command = f'clamscan.exe -i -o -r -l ..\\Logs\\ClamLog.log --detect-pua=yes --remove=no --normalize=no --exclude-pua=Win.Packer "{input_dir}"'
subprocess.run(command, shell=True, check=False)

# change working directory back to script's directory
os.chdir('..')

# Parse the log contents to get the Filename and malware name
table = PrettyTable(['Full Pathname', 'MD5', 'Malware Name'])
table.align = "l"
# Open the log file from ClamAV
with open('Logs\\ClamLog.log') as f:
    data = f.readlines()

# extract the data from the log
rows = []
rows = []
for line in data:
    if "FOUND" in line:
        full_pathname = line.split("FOUND")[0].rsplit(":", 1)[0]  # Remove only the last colon
        md5 = calculate_md5(full_pathname)
        malware_name = line.split(":")[-1].split("FOUND")[0].strip()
        rows.append([
            full_pathname,
            md5,
            malware_name
        ])

# create the table and add the rows
table = PrettyTable()
table.field_names = ['Full Pathname', 'MD5', 'Malware Name']
table.align = "l"
for row in rows:
    table.add_row(row)

# print the table
print(table)

# connect to the SQLite3 database
conn = sqlite3.connect('db/MalwareScan.db')
c = conn.cursor()

# insert the scan results into the MalwareScan table
for row in rows:
    full_pathname, md5, malware_name = row
    filename = os.path.basename(full_pathname)  # extract just the filename from the full path
    c.execute("SELECT MD5 FROM MalwareScan WHERE md5=?", (md5,))
    result = c.fetchone()
    if result is None:
        c.execute("INSERT INTO MalwareScan (filename, md5, clamav) VALUES (?, ?, ?)", (filename, md5, malware_name))
    else:
        c.execute("UPDATE MalwareScan SET clamav=? WHERE md5=?", (malware_name, md5))

# commit changes and close the database connection
conn.commit()
conn.close()
