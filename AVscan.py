import os
import sys
import sqlite3

# List of Python scripts to run for virus scanning
python_scripts = ['AviraScan.py', 'DWscan.py', 'IkarusScan.py', 'EmsiScan.py', 'McAfeeScan.py', 'ClamAVScan.py', 'MDScanDB.py', 'KVRTScan.py', ]

# Get the input directory from the command line argument
input_dir = sys.argv[1]

# Delete all files in the C:\TEMP\LOG\ directory
log_dir = r'c:\Apps\AV\Logs'
for filename in os.listdir(log_dir):
    file_path = os.path.join(log_dir, filename)
    if os.path.isfile(file_path):
        os.remove(file_path)

# Connect to the SQLite3 database or create it if it doesn't exist
db_conn = sqlite3.connect('db/MalwareScan.db')

# Create the MalwareScan table if it doesn't exist
db_conn.execute('CREATE TABLE IF NOT EXISTS MalwareScan (Filename TEXT, MD5 TEXT, Avira TEXT, DrWeb TEXT, Ikarus TEXT, Emsisoft TEXT, McAfee TEXT, ClamAV TEXT, MS_Defender TEXT, KVRT TEXT)')
db_conn.commit()
db_conn.close()

# Loop through the list of Python scripts and run each one on the input directory
for script in python_scripts:
    script_path = os.path.join(os.getcwd(), script)
    command = f'python {script_path} {input_dir}'
    os.system(command)

# Run the CountDB.py script
countdb_script = 'CountDB.py'
countdb_path = os.path.join(os.getcwd(), countdb_script)
command_countdb = f'python {countdb_path}'
os.system(command_countdb)
