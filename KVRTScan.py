import subprocess
import argparse
import os
import hashlib
import sys
from prettytable import PrettyTable
import sqlite3
import xml.etree.ElementTree as ET

# Define the argument parser
parser = argparse.ArgumentParser(description='Scan a directory using Kaspersky Virus Removal Tool (KVRT) and save the results to a SQLite3 database.')
parser.add_argument('directory', metavar='directory', type=str, help='The directory to scan')
args = parser.parse_args()

# get input directory from command line argument
input_dir = sys.argv[1]

# run KVRT scan on the input directory
command = [
    'kvrt.exe',
    '-accepteula',
    '-dontencrypt',
    '-noads',
    '-silent',
    '-fixednames',
    '-details',
    '-custom',
    input_dir
]
subprocess.run(command, check=False)
subprocess.run(["python.exe", "KVRT_newlog.py"])

tree = ET.parse('Logs/KVRT_new.log')
root = tree.getroot()

# create a PrettyTable to display the results
table = PrettyTable()
table.field_names = ["Filename", "MD5", "Malware name"]
table.align = "l"

# create a list to hold the results to be added to the database
results = []

for event in root.iter('Event'):
    fullpathname = event.get('Object')
    filename = event.get('Object').split('\\')[-1]
    malware_name = event.get('Info')
    
    # calculate the MD5 hash of the file
    with open(fullpathname, "rb") as f:
        file_bytes = f.read()
        md5 = hashlib.md5(file_bytes).hexdigest()
    
    # add the file's information to the PrettyTable and results list
    table.add_row([fullpathname, md5, malware_name])
    results.append((fullpathname, md5, malware_name))

# print the PrettyTable
print(table)

# connect to the SQLite3 database
conn = sqlite3.connect('db/MalwareScan.db')
c = conn.cursor()

# insert the scan results into the MalwareScan table
for row in results:
    fullpathname, md5, malware_name = row
    filename = os.path.basename(fullpathname)  # extract just the filename from the full path
    c.execute("SELECT MD5 FROM MalwareScan WHERE md5=?", (md5,))
    result = c.fetchone()
    if result is None:
        c.execute("INSERT INTO MalwareScan (filename, md5, kvrt) VALUES (?, ?, ?)", (filename, md5, malware_name))
    else:
        c.execute("UPDATE MalwareScan SET kvrt=? WHERE md5=?", (malware_name, md5))

# commit changes and close the database connection
conn.commit()
conn.close()
