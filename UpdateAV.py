import os
import requests
from bs4 import BeautifulSoup
import subprocess
import zipfile
import shutil
import hashlib

def update_avira_scancl():
    avira_folder = r"C:\Apps\AV\Avira"
    fusebundle_exe = os.path.join(avira_folder, "FuseBundle", "fusebundle.exe")
    fusebundle_zip = os.path.join(avira_folder, "FuseBundle", "install", "vdf_fusebundle.zip")
    avira_scancl_exe = os.path.join(avira_folder, "scancl.exe")

    # Check if Avira folder and files exist
    if not os.path.exists(avira_folder):
        print("Avira folder not found.")
        return
    if not os.path.exists(fusebundle_exe):
        print("FuseBundle executable not found.")
        return
    if not os.path.exists(fusebundle_zip):
        print("FuseBundle ZIP file not found.")
        return

    # Run fusebundle to update Avira
    print("Running FuseBundle to update Avira...")
    try:
        subprocess.run(fusebundle_exe, shell=True, check=True)
        print("FuseBundle update completed.")
    except subprocess.CalledProcessError as e:
        print(f"Error updating Avira with FuseBundle: {e}")
        return

    # Extract the ZIP file
    print("Extracting FuseBundle ZIP file...")
    try:
        with zipfile.ZipFile(fusebundle_zip, 'r') as zip_ref:
            zip_ref.extractall(avira_folder)
        print("FuseBundle ZIP file extracted successfully.")
    except Exception as e:
        print(f"Error extracting FuseBundle ZIP file: {e}")
        return

    print("Avira ScanCL update completed successfully.")

def update_clamav():
    clamav_folder = r"C:\Apps\AV\ClamAV"
    freshclam_exe = os.path.join(clamav_folder, "freshclam.exe")
    sigupdate_bat = os.path.join(clamav_folder, "SigUpdate", "sigupdate.bat")

    # Check if ClamAV folder and files exist
    if not os.path.exists(clamav_folder):
        print("ClamAV folder not found.")
        return
    if not os.path.exists(freshclam_exe):
        print("Freshclam executable not found.")
        return
    if not os.path.exists(sigupdate_bat):
        print("SigUpdate batch script not found.")
        return

    # Run freshclam to update ClamAV
    print("Running freshclam to update ClamAV...")
    try:
        subprocess.run(freshclam_exe, shell=True, check=True)
        print("ClamAV update completed successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Error updating ClamAV with freshclam: {e}")
        return

    # Change directory to SigUpdate directory
    sigupdate_dir = os.path.dirname(sigupdate_bat)
    os.chdir(sigupdate_dir)

    # Run sigupdate.bat for additional ClamAV updates
    print("Running sigupdate.bat for additional ClamAV updates...")
    try:
        subprocess.run(sigupdate_bat, shell=True, check=True)
        print("Additional ClamAV updates completed successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Error running sigupdate.bat for ClamAV updates: {e}")
        return

    # Change back to the original directory
    os.chdir(clamav_folder)
    
def update_drwebcl():
    drwebcl_folder = r"C:\Apps\AV\DrWebCL"
    update_cmd = os.path.join(drwebcl_folder, "2.update.cmd")

    # Check if DrWebCL folder and files exist
    if not os.path.exists(drwebcl_folder):
        print("DrWebCL folder not found.")
        return
    if not os.path.exists(update_cmd):
        print("Update command script not found.")
        return

    # Change directory to DrWebCL directory
    os.chdir(drwebcl_folder)

    # Run update.cmd to update DrWebCL
    print("Running update.cmd to update DrWebCL...")
    try:
        subprocess.run(update_cmd, shell=True, check=True)
        print("DrWebCL update completed successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Error updating DrWebCL: {e}")
        return

    # Change back to the original directory
    os.chdir(os.path.dirname(drwebcl_folder))
    
def update_emsisoft():
    eek_folder = r"C:\Apps\AV\EEK\bin64"
    a2cmd_exe = os.path.join(eek_folder, "a2cmd.exe")

    # Check if EEK folder and files exist
    if not os.path.exists(eek_folder):
        print("EEK folder not found.")
        return
    if not os.path.exists(a2cmd_exe):
        print("a2cmd.exe not found.")
        return

    # Run a2cmd.exe to update Emsisoft
    print("Running a2cmd.exe to update Emsisoft...")
    try:
        subprocess.run([a2cmd_exe, "/update"], check=True)
        print("Emsisoft update completed successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Error updating Emsisoft: {e}")
        return

def download_file(url, download_folder):
    filename = os.path.basename(url)
    download_path = os.path.join(download_folder, filename)
    print(f"Downloading {filename}...")
    try:
        with requests.get(url, stream=True) as r:
            r.raise_for_status()
            with open(download_path, 'wb') as f:
                for chunk in r.iter_content(chunk_size=8192):
                    f.write(chunk)
        print(f"Download completed: {filename}")
        return download_path
    except Exception as e:
        print(f"Error downloading {filename}: {e}")
        return None

def extract_archive(archive_path, extract_folder):
    try:
        with zipfile.ZipFile(archive_path, 'r') as zip_ref:
            zip_ref.extractall(extract_folder)
        print(f"Extraction completed: {archive_path}")
    except Exception as e:
        print(f"Error extracting {archive_path}: {e}")

def update_rose_malware_scanner():
    # Set the URL and download directory
    URL = "http://rose-swe.bplaced.net/dl"
    download_folder = r"C:\Apps\AV\RMS\Update"

    # Fetch md5sums file
    md5sums_url = f"{URL}/md5sums.md5"
    md5sums_file = download_file(md5sums_url, download_folder)

    if md5sums_file:
        # Read md5sums file and download/update files
        with open(md5sums_file, 'r') as file:
            for line in file:
                md5sum, filename = line.strip().split()
                file_url = f"{URL}/{filename}"
                file_path = os.path.join(download_folder, filename)

                # Download file if it doesn't exist or if md5sum is different
                if not os.path.exists(file_path) or hashlib.md5(open(file_path, 'rb').read()).hexdigest() != md5sum:
                    download_file(file_url, download_folder)
                else:
                    print(f"{filename}: No newer version available!")

        print("Rose Malware Scanner update completed successfully.")

        # Extract RMS archive if present
        rms_archive_path = None
        for file in os.listdir(download_folder):
            if file.startswith("rms_") and file.endswith(".zip"):
                rms_archive_path = os.path.join(download_folder, file)
                extract_folder = os.path.join(download_folder, "RMS")
                extract_archive(rms_archive_path, extract_folder)
                break

        # Copy files from RMS folder to RMS main folder
        if rms_archive_path:
            for root, dirs, files in os.walk(extract_folder):
                for file in files:
                    src_path = os.path.join(root, file)
                    dest_path = os.path.join(r"C:\Apps\AV\RMS", file)
                    shutil.copy(src_path, dest_path)

        # Copy files from RMS\Windows folder to RMS main folder
        rms_windows_folder = os.path.join(extract_folder, "Windows")
        if os.path.exists(rms_windows_folder):
            for file in os.listdir(rms_windows_folder):
                src_path = os.path.join(rms_windows_folder, file)
                dest_path = os.path.join(r"C:\Apps\AV\RMS", file)
                shutil.copy(src_path, dest_path)
                

def update_xvirus():
    xvirus_exe = r"C:\Apps\AV\Xvirus\XvirusCLI.exe"

    # Run XvirusCLI.exe with "update" argument
    try:
        subprocess.run([xvirus_exe, "update"], check=True)
        print("Xvirus update completed successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Error updating Xvirus: {e}")
         
if __name__ == "__main__":
    print("Updating Avira ScanCL...")
    update_avira_scancl()
    print("\nUpdating ClamAV...")
    update_clamav()
    #print("\nUpdating DrWebCL...")
    #update_drwebcl()
    print("\nUpdating Emsisoft...")
    update_emsisoft()
    # Updating Ikarus Virus definitions
    subprocess.run(["python.exe", "c:\\Apps\\AV\\update-ikarus.py"])
    print("Ikarus virus definitions have been updated.")
    # Updating McAfee Virus definitions
    subprocess.run(["python.exe", "c:\\Apps\\AV\\update-mcafee.py"])
    print("McAfee DAT files have been updated.")
    update_rose_malware_scanner()
    print("\nUpdating Xvirus...")
    update_xvirus()

