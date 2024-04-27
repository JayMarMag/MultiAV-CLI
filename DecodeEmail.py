import os
import sys
import email
import shutil
from email.header import decode_header
import re

def sanitize_filename(filename):
    # Replace invalid characters with underscores
    return re.sub(r'[^\w\-_.]', '_', filename)

def decode_eml(eml_file, output_folder):
    try:
        with open(eml_file, 'r', encoding='utf-8') as f:
            msg = email.message_from_file(f)
    except UnicodeDecodeError:
        # If UTF-8 decoding fails, try another encoding or treat the file as binary
        with open(eml_file, 'rb') as f:
            msg = email.message_from_bytes(f.read())

    # Create a subfolder named 'Extract' if it doesn't exist
    extract_folder = os.path.join(output_folder, 'Extract')
    os.makedirs(extract_folder, exist_ok=True)

    for part in msg.walk():
        if part.get_content_maintype() == 'multipart':
            continue
        content_type = part.get_content_type()
        filename = part.get_filename()
        
        # If the part has no filename, generate one based on Content-Disposition or MIME type
        if not filename:
            filename = part.get_param("name") or "attachment"
            if filename:
                filename = decode_header(filename)[0][0]
                if isinstance(filename, bytes):
                    filename = filename.decode("utf-8", errors="replace")
            else:
                filename = "attachment"

        # Sanitize the filename
        filename = sanitize_filename(filename)

        # Generate a unique filename if the filename is empty after sanitizing
        if not filename.strip():
            filename = "attachment"
        filename = os.path.join(extract_folder, filename)

        # Decode the attachment
        decoded_content = part.get_payload(decode=True)
        if decoded_content:
            with open(filename, 'wb') as attachment:
                attachment.write(decoded_content)
                    
if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python script.py <eml_folder> <output_folder>")
        sys.exit(1)
    
    eml_folder = sys.argv[1]
    output_folder = sys.argv[2]

    # Iterate over .eml files in the input folder
    for filename in os.listdir(eml_folder):
        if filename.endswith('.eml'):
            eml_file = os.path.join(eml_folder, filename)
            decode_eml(eml_file, output_folder)
    
    print("Decoding complete. Extracted contents can be found in the 'Extract' subfolder of the output folder.")
