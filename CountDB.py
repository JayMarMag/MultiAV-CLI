import sqlite3
from prettytable import PrettyTable

# Connect to the MalwareScan database
conn = sqlite3.connect('db/MalwareScan.db')

# Get a cursor object
cursor = conn.cursor()

# Execute the query to get the number of rows for each column in the MalwareScan table
cursor.execute("SELECT COUNT(MD5), COUNT(Avira), COUNT(DrWeb), COUNT(Ikarus), COUNT(Emsisoft), COUNT(McAfee), COUNT(ClamAV), COUNT(MS_Defender), COUNT(KVRT) FROM MalwareScan")

# Fetch the results of the query
results = cursor.fetchone()

# Calculate the missed samples for each scanner
missed_avira = results[0] - results[1]
missed_drweb = results[0] - results[2]
missed_ikarus = results[0] - results[3]
missed_emsisoft = results[0] - results[4]
missed_mcafee = results[0] - results[5]
missed_clamav = results[0] - results[6]
missed_MSD = results[0] - results[7]
missed_kvrt = results[0] - results[8]

# Calculate the percentages for each column
md5_count = results[0]
percentages = [(count / md5_count) * 100 if md5_count != 0 else 0 for count in results]

# Create a PrettyTable to display the results
table = PrettyTable()
table.align = "l"
table.field_names = ['Column', 'Count', 'Missed', 'Percentage']
table.add_row(['Total MD5', results[0], '-', '100%'])
table.add_row(['Avira', results[1], missed_avira, f'{percentages[1]:.2f}%'])
table.add_row(['DrWeb', results[2], missed_drweb, f'{percentages[2]:.2f}%'])
table.add_row(['Ikarus', results[3], missed_ikarus, f'{percentages[3]:.2f}%'])
table.add_row(['Emsisoft', results[4], missed_emsisoft, f'{percentages[4]:.2f}%'])
table.add_row(['McAfee', results[5], missed_mcafee, f'{percentages[5]:.2f}%'])
table.add_row(['ClamAV', results[6], missed_clamav, f'{percentages[6]:.2f}%'])
table.add_row(['MS Defender', results[7], missed_MSD, f'{percentages[7]:.2f}%'])
table.add_row(['KVRT', results[8], missed_kvrt, f'{percentages[8]:.2f}%'])

# Print the table
print(table)

# Close the connection to the database
conn.close()
