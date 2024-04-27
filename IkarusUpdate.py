import re
import hashlib
import os
import subprocess
import time
import requests

def get_t3sigs_md5():
    # URL of the update page
    url = "https://updates.ikarus.at/updates/update.html"

    try:
        # Download the HTML content
        response = requests.get(url)
        response.raise_for_status()

        # Search for the line containing "T3 VDB"
        pattern = r'T3 VDB.*?([0-9a-fA-F]{32})'
        match = re.search(pattern, response.text)
        if match:
            md5_hash = match.group(1)
            return md5_hash
        else:
            print("Information for t3sigs.vdb not found on the update page")
            return None

    except Exception as e:
        print(f"Error downloading or parsing HTML: {e}")
        return None

def download_t3sigs():
    # URL of the latest t3sigs.vdb
    download_url = "http://updates.ikarus.at/cgi-bin/t3download.pl/t3sigs.vdb"
    # Path to existing t3sigs.vdb
    existing_file_path = "c:/Apps/AV/Ikarus/t3sigs.vdb"
    # Path to download the new file
    temp_download_path = "c:/Apps/AV/Ikarus/t3sigs_temp.vdb"
    # Final destination path
    final_destination_path = "c:/Apps/AV/Ikarus/t3sigs_new.vdb"

    # Get MD5 hash of the existing file
    existing_md5 = None
    if os.path.exists(existing_file_path):
        with open(existing_file_path, "rb") as file:
            existing_md5 = hashlib.md5(file.read()).hexdigest()

    # Get MD5 hash from the update page
    new_md5 = get_t3sigs_md5()

    if existing_md5 == new_md5:
        print("Existing t3sigs.vdb is up to date.")
    else:
        try:
            # Download the latest t3sigs.vdb using wget
            subprocess.run(["wget", "--quiet", "-O", temp_download_path, download_url])

            # Move the file to the final destination
            if os.path.exists(temp_download_path):
                os.replace(temp_download_path, final_destination_path)
                print("t3sigs.vdb downloaded successfully and moved to final destination.")
            else:
                print("Download failed.")
        except Exception as e:
            print(f"Error downloading or updating t3sigs.vdb: {e}")


if __name__ == "__main__":
    download_t3sigs()
