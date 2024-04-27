import requests
import re
import hashlib
from prettytable import PrettyTable
import os

url = "https://updates.ikarus.at/updates/update.html"
response = requests.get(url)

# File paths for local files
t3sigs_path = r"Ikarus\t3sigs.vdb"
t3scan_path = r"Ikarus\ikarust3scan.exe"
t3scan_w64_path = r"Ikarus\ikarust3scan_w64.exe"

# List of local files and their corresponding online hash value and download url
files = [
    (t3sigs_path, re.search(r'<tr class="grey"><td>T3 VDB</td><td>.*</td><td>.*</td><td>&nbsp;(\w+)</td>', response.text).group(1), "http://updates.ikarus.at/cgi-bin/t3download.pl/t3sigs.vdb"),
    (t3scan_path, re.search(r'<tr class="grey"><td>T3 Commandline<br />Scanner</td><td>.*</td><td>.*</td><td>&nbsp;(\w+)</td>', response.text).group(1), "http://updates.ikarus.at/cgi-bin/t3download.pl/ikarust3scan.exe"),
    (t3scan_w64_path, re.search(r'<tr class="grey"><td>T3 Commandline<br />Scanner \(64bit\)</td><td>.*</td><td>.*</td><td>&nbsp;(\w+)</td>', response.text).group(1), "http://updates.ikarus.at/cgi-bin/t3download.pl/ikarust3scan_w64.exe")
]

table = PrettyTable(["File", "Local MD5", "Remote MD5", "Updated?"])
table.align = 'l'

for file_path, online_hash, download_url in files:
    with open(file_path, "rb") as f:
        content = f.read()
    local_hash = hashlib.md5(content).hexdigest()
    updated = "Yes" if local_hash == online_hash else "No"
    table.add_row([file_path, local_hash, online_hash, updated])

print(table)

for file_path, online_hash, download_url in files:
    with open(file_path, "rb") as f:
        content = f.read()
    local_hash = hashlib.md5(content).hexdigest()
    if local_hash == online_hash:
        continue
    else:
        download = input(f"Do you want to download the latest update for {file_path}? [Y/n]")
        if download.lower() in ["yes", "y"]:
            if file_path == t3sigs_path:
                backup_path = file_path + ".backup"
                if os.path.exists(backup_path):
                    os.remove(backup_path)
                    print(f"Deleted existing backup file: {backup_path}")
                os.rename(file_path, backup_path)
                print(f"Renamed {file_path} to {backup_path}")
            os.system(f"aria2c -x 8 -s 5 {download_url} -d {os.path.dirname(file_path)} -o {os.path.basename(file_path)}")
            print(f"{file_path} has been updated.")
        else:
            continue

