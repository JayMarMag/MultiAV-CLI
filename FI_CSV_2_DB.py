import csv
import sqlite3

# Connect to the database or create it if it doesn't exist
conn = sqlite3.connect("db/FileIdent.db")
cursor = conn.cursor()

# Create the TrID_Results table
cursor.execute("""
CREATE TABLE IF NOT EXISTS TrID_Results (
    Filename text,
    TrID text
)
""")

# Read data from the TrID CSV file
with open("db/FI-TrID.csv", "r") as trid_csv:
    reader = csv.reader(trid_csv)
    next(reader)  # Skip the header row
    data = [(row[0], row[1]) for row in reader]

# Insert the TrID data into the TrID_Results table
cursor.executemany("""
INSERT INTO TrID_Results (Filename, TrID)
VALUES (?, ?)
""", data)

# Create the FIDO_Results table
cursor.execute("""
CREATE TABLE IF NOT EXISTS FIDO_Results (
    Filename text,
    PUID text,
    Format_Name text,
    Signature_Name text,
    MimeType text,
    MatchType text
)
""")

# Read data from the FIDO CSV file
with open("db/FI-FIDO.csv", "r") as fido_csv:
    reader = csv.reader(fido_csv)
    next(reader)  # Skip the header row
    data = [(row[0], row[1], row[2], row[3], row[4], row[5]) for row in reader]

# Insert the FIDO data into the FIDO_Results table
cursor.executemany("""
INSERT INTO FIDO_Results (Filename, PUID, Format_Name, Signature_Name, MimeType, MatchType)
VALUES (?, ?, ?, ?, ?, ?)
""", data)

# Commit the changes and close the connection
conn.commit()
conn.close()
