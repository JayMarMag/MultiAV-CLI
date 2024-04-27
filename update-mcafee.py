import requests
import os
import zipfile

url = "http://update.nai.com/products/commonupdater/gdeltaavv.ini"
response = requests.get(url)

with open("gdeltaavv.ini", "wb") as f:
    f.write(response.content)

with open("gdeltaavv.ini", "r") as f:
    lines = f.readlines()

current_version = lines[3].split("=")[1].strip()
current_version = current_version.strip()

folder_name = "McAfee"
file_name = f"McAfee/DATS/avvdat-{current_version}.zip"
#Final_file_name = f"McAfee\DATS\avvdat-{current_version}.zip"
print(current_version)

if not os.path.exists(file_name):
    file_url = f"http://update.nai.com/products/commonupdater/avvdat-{current_version}.zip"
    response = requests.get(file_url)
    

    with open(file_name, "wb") as f:
        f.write(response.content)
    print(f"File {file_name} downloaded.")
else:
    print(f"File {file_name} already exists.")

with zipfile.ZipFile(file_name, "r") as zip_ref:
    zip_ref.extractall(folder_name)
    print(f"File {file_name} extracted to {folder_name}.")
    
#os.rename(file_name, f"McAfee\DATS\avvdat-{current_version}.zip")