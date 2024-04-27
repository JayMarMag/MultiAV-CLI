import os
import subprocess
from prettytable import PrettyTable
import re
import concurrent.futures
from tqdm import tqdm
import sqlite3
import csv

db_path = 'db/FileIdent.db'

trid_table = PrettyTable(['Filename', 'TrID'])
fido_table = PrettyTable(['Filename', 'PUID', 'Format Name', 'Signature Name', 'MimeType', 'MatchType'])
trid_table.align = 'l'
fido_table.align = 'l'

folder_path = input("Enter the path of the folder containing the files to be processed: ")

def process_file(filename):
    file_path = os.path.join(folder_path, filename)
    
    # Run TrID on file
    trid_output = subprocess.run(['trid', '-n:1', file_path], capture_output=True, text=True)
    trid_result = trid_output.stdout.strip().split("\n")[-1]
    trid_result = re.sub(r"\s\(\d+(\/\d+)+\)$", "", trid_result).replace('(generic)', '').strip()
    trid_table.add_row([filename, trid_result])

    # Run FIDO on file
    fido_output = subprocess.run(['fido', '-q', file_path], capture_output=True, text=True)
    fido_result = fido_output.stdout
    if fido_result.startswith("KO"):
        fido_table.add_row([filename, "Unknown!", "Unknown!", "Unknown!", "Unknown!", "Unknown!"])
    else:
        _, _, puid, format_name, signature_name, _, _, mime_type, match_type = fido_result.split(',')
        fido_table.add_row([filename, puid, format_name, signature_name, mime_type, match_type])
        
        
# Run the process_file function in parallel using 4 threads
with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
    files = os.listdir(folder_path)
    future_to_file = {executor.submit(process_file, filename): filename for filename in files}
    for future in tqdm(concurrent.futures.as_completed(future_to_file), total=len(files)):
        file = future_to_file[future]
    
print("TrID Results:")
print(trid_table)
print("\nFIDO Results:")
print(fido_table)

with open('db/FI-TrID.csv', 'w', newline='') as f:
    writer = csv.writer(f)
    writer.writerow(['Filename', 'TrID'])
    for row in trid_table.rows:
        writer.writerow(row)

with open('db/FI-FIDO.csv', 'w', newline='') as f:
    writer = csv.writer(f)
    writer.writerow(['Filename', 'PUID', 'Format Name', 'Signature Name', 'MimeType', 'MatchType'])
    for row in fido_table.rows:
        writer.writerow(row)
        
subprocess.run(["python", "FI_CSV_2_DB.py"])
