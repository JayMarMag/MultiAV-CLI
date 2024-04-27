import subprocess
import argparse
import os
import hashlib
import sys
import sqlite3
from prettytable import PrettyTable

# Define the argument parser
parser = argparse.ArgumentParser(description='Scan a directory using the Avira ScanCL, McAfee, ClamAV, Emsisoft, Ikarus, TrendMicro, MS-Defender, and KVRT and save the results to a SQLite3 database.')
parser.add_argument('directory', metavar='directory', type=str, help='The directory to scan')
args = parser.parse_args()

# get input directory from command line argument
input_dir = sys.argv[1]

# change working directory to Avira/
os.chdir('Avira')

# run Avira ScanCL on the input directory
command = f'scancl.exe /a /z --withtype=all --heurlevel=3 --log=../Logs/Avira.log --logformat=singleline --stats "{input_dir}"'
subprocess.run(command, shell=True, check=False)

# change working directory back to script's directory
os.chdir('..')

# Parse the log contents to get the Filename and Malware name
scan_results = []
with open(os.path.join('Logs', 'Avira.log'), 'r', encoding='utf-8', errors='ignore') as f:
    lines = f.readlines()
    for line in lines:
        if 'ALERT:' in line:
            avira_malware_name = line.split('[', 1)[1].split(']')[0]
            filepath = line.split('] ')[1].split(' <<<')[0].split(' --> ')[0]
            hash_md5 = hashlib.md5()
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_md5.update(chunk)
            md5 = hash_md5.hexdigest()
            scan_results.append((filepath, md5, avira_malware_name))

# Connect to the SQLite3 database or create it if it doesn't exist
db_conn = sqlite3.connect('db/MalwareScan.db')

# Insert the scan results into the MalwareScan table, skipping files with existing MD5 hash
for result in scan_results:
    md5 = result[1]
    if not db_conn.execute('SELECT MD5 FROM MalwareScan WHERE MD5 = ?', (md5,)).fetchone():
        db_conn.execute('INSERT INTO MalwareScan (Filename, MD5, Avira) VALUES (?, ?, ?)', (os.path.basename(result[0]), result[1], result[2]))

# Commit the changes and close the database connection
db_conn.commit()
db_conn.close()

# Display the scan results in a pretty table
table = PrettyTable(['Filename', 'MD5 Hash', 'Malware Name'])
table.align = "l"
for result in scan_results:
    table.add_row([os.path.basename(result[0]), result[1], result[2]])
print(table)
