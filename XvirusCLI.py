import os
import json
import sqlite3
import hashlib
from prettytable import PrettyTable
from termcolor import colored
from tqdm import tqdm
import subprocess
import csv

folder_path = input("Enter the folder path: ")
x = PrettyTable()
x.field_names = ["Full Pathname", "IsMalware", "Malware name", "AI Malware Detection Score", "MD5 Hash"]
x.align["Full Pathname"] = "l"
malware_count = 0
crash_list = []
crashes = []

# create the db folder if not exist
if not os.path.exists("db"):
    os.makedirs("db")

# connect to or create the database
conn = sqlite3.connect("db/xvirus.db")
cursor = conn.cursor()

# create a table to store the scan results
conn.execute('''CREATE TABLE IF NOT EXISTS  xvirus_results
             (filename TEXT, malware_name TEXT, malware_score REAL, md5_hash TEXT)''')

for root, dirs, files in os.walk(folder_path):
    with tqdm(total=len(files), desc=root, unit='files') as pbar:
        for file in files:
            file_path = os.path.join(root, file)
            file_path = file_path.replace(" ", "")
            try:
                scan_command = f'XvirusCLI\XvirusCLI.exe scan "{file_path}"'
                output = subprocess.run(scan_command, capture_output=True, text=True)
                output_json = json.loads(output.stdout)
            except:
                crash_list.append(file_path)
                print("===== XvirusCLI crash on => ", file_path)
                continue

            if "AI" in output_json["Name"] and output_json["IsMalware"] == False:
                malware_name = "Malware by AI"
                malware_score = round(output_json["MalwareScore"]*100, 2)
                if malware_score == -100:
                    malware_score = 100
                else:
                    malware_score = malware_score
                if malware_score >= 81:
                    malware_score_color = "red"
                elif malware_score >= 51:
                    malware_score_color = "magenta"
                elif malware_score >= 1:
                    malware_score_color = "yellow"
                else:
                    malware_score_color = "white"
            elif "AI" in output_json["Name"] and output_json["IsMalware"] == True:
                malware_name = "Malware"
                malware_score = round(output_json["MalwareScore"]*100, 2)
                if malware_score == -100:
                    malware_score = 100
                else:
                    malware_score = malware_score
                if malware_score >= 81:
                    malware_score_color = "red"
                elif malware_score >= 51:
                    malware_score_color = "magenta"
                elif malware_score >= 1:
                    malware_score_color = "yellow"
                else:
                    malware_score_color = "white"
            else:
                malware_name = output_json["Name"]
                malware_score = "N/A"
                malware_score_color = "white"
    
            if output_json["IsMalware"] == True:
                malware_count += 1
                is_malware = colored("True", 'red')               
            else:
                is_malware = colored("False", 'green')

            # calculate the md5 hash of the file
            md5_hash = hashlib.md5()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    md5_hash.update(chunk)
            md5_hash_hex = md5_hash.hexdigest()

            x.add_row([file_path, is_malware, malware_name, colored(str(malware_score) + "%", malware_score_color), md5_hash_hex])

            # insert the scan results to the table
            if output_json["IsMalware"] == True:
                cursor.execute("SELECT COUNT(*) FROM xvirus_results WHERE md5_hash = ?", (md5_hash_hex,))
                count = cursor.fetchone()[0]
                if count == 0:
                    conn.execute("INSERT INTO xvirus_results (filename, malware_name, malware_score, md5_hash) VALUES (?,?,?,?)", (file_path, malware_name, malware_score, md5_hash_hex))
                    conn.commit()
            else:
                pass
            pbar.update()

        # output the crash list to a CSV file
    with open("XvirusCLI\crashlist.csv", "w", newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["File path"])
        writer.writerows([[i] for i in crash_list])

print(x)
print("Total number of malwares detected:", malware_count)

# close the database connection
conn.close()
