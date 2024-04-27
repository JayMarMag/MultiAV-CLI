import os
import shutil

folder_path = "c:\KVRT2020_Data\Reports\\"
file_prefix = "details_"
destination = "logs/KVRT_new.log"

files = [f for f in os.listdir(folder_path) if f.startswith(file_prefix)]
if files:
    latest_file = max(files, key=lambda x: os.path.getctime(folder_path + x))
    source_file = folder_path + latest_file
    with open(source_file, 'r', encoding='utf-8') as f:
        content = f.readlines()
        
    with open(destination, 'w', encoding='utf-8') as f:
        skip_lines = False
        for i, line in enumerate(content):
            if 'Action="Checked"' in line:
                continue
            if "</Block>" in line:
                skip_lines = True
                f.write(line)
            if not skip_lines or i in (len(content)-2, len(content)-1):
                f.write(line)
else:
    print("No file with the prefix 'details_' found in the folder.")
