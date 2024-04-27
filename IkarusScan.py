import subprocess
import argparse
import os
import hashlib
import sys
from prettytable import PrettyTable
import sqlite3
import chardet
import re


# Define the argument parser
parser = argparse.ArgumentParser(description='Scan a directory using multiple antivirus software and save the results to a SQLite3 database.')
parser.add_argument('directory', metavar='directory', type=str, help='The directory to scan')
args = parser.parse_args()

# get input directory from command line argument
input_dir = sys.argv[1]


# run Ikarus scan on the input directory
command = f'Ikarus\\T3Scan_w64.exe -l Logs\\Ikarus.log {input_dir}'
subprocess.run(command, shell=True, check=False)
command12 = "CheckEnc.bat"
print(command12)
subprocess.run(command12, shell=True)
print("Logs encoding fixed.")

# Parse the log contents to get the Filename and Malware name
table = PrettyTable(['Filename', 'MD5 Hash', 'Malware Name'])
table.align = "l"

with open("Logs/Ikarus.log", "rb") as f:
    content = f.read()

# Step 2: Use chardet to detect the type of encoding
encoding = chardet.detect(content)["encoding"]

# Step 3: Clean up the logs
lines = content.decode(encoding).split("\n")
cleaned_lines = [line for line in lines if len(re.findall(":", line)) <= 1]

# Step 4: Write the cleaned log file
with open("Logs/IkarusCleaned.log", "w", encoding="UTF-8") as f:
    f.write("\n".join(cleaned_lines))
  
# extract the data from the log
rows = []
with open('Logs/IkarusCleaned.log', encoding=encoding) as f:
    for line in f:
        if 'found' in line:
            # get malware name
            malware_name = line.split("'")[1]
            
            # check for 2 colons in the line
            if line.count(':') == 2:
                # remove everything after the second colon, including the colon itself
                filepath = line.split(':')[0] + line.split(':')[1]
            else:
                # get filepath before "- Signature" string
                filepath = line.split("- Signature")[0].strip()
                
            filename = os.path.basename(filepath)
            abs_path = os.path.join(input_dir, filepath)
            if os.path.exists(abs_path):
                md5_hash = hashlib.md5(open(abs_path, 'rb').read()).hexdigest()
                rows.append([
                    filename,
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
    # check if md5 hash already exists in database
    c.execute('SELECT MD5 FROM MalwareScan WHERE MD5 = ?', (row[1],))
    result = c.fetchone()
    if result:
        # update the Ikarus column with the malware name
        c.execute('UPDATE MalwareScan SET Ikarus = ? WHERE MD5 = ?', (row[2], row[1]))
    else:
        # insert a new row in the database
        c.execute('INSERT INTO MalwareScan (Filename, MD5, Ikarus) VALUES (?, ?, ?)', (row[0], row[1], row[2]))
conn.commit()
conn.close()

# print the table
for row in rows:
    table.add_row(row)
print(table)