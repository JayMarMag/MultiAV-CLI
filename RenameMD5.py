import os
import sys
import hashlib

def md5_rename(folder_path):
    for filename in os.listdir(folder_path):
        file_path = os.path.join(folder_path, filename)
        if os.path.isfile(file_path):
            # Calculate MD5 hash
            with open(file_path, 'rb') as f:
                content = f.read()
            md5_hash = hashlib.md5(content).hexdigest()

            # Get file extension in lowercase
            _, extension = os.path.splitext(filename)
            extension = extension.lower()

            # New filename with MD5 hash in uppercase and original extension
            new_filename = md5_hash.upper() + extension
            new_file_path = os.path.join(folder_path, new_filename)

            # Check if the new filename already exists
            if os.path.exists(new_file_path):
                print(f"File {new_filename} already exists. Skipping...")
                os.remove(file_path)
            else:
                # Rename the file
                os.rename(file_path, new_file_path)
                print(f"Renamed {filename} to {new_filename}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <folder_path>")
        sys.exit(1)

    folder_path = sys.argv[1]
    if not os.path.isdir(folder_path):
        print("Invalid folder path!")
        sys.exit(1)

    md5_rename(folder_path)
