import sys
import re

input_file = sys.argv[1]
output_file = input_file.replace(".log", ".xml")

with open(input_file, "r") as f:
    data = f.read()

# find all the threat blocks
threat_blocks = re.findall(r"----------------------------- Threat information ------------------------------\n(.*?)\n-------------------------------------------------------------------------------", data, re.DOTALL)

# start creating the xml output
output = "<?xml version='1.0' encoding='UTF-8'?>\n<malware>\n"

# process each threat block
for threat_block in threat_blocks:
    # extract the malware name
    malware_name = re.search(r"Threat\s+:\s+(.*)", threat_block).group(1)
    if malware_name == "Unknown":
        continue

    # start the threat section in the xml output
    output += f"\t<threat name='{malware_name}'>\n"

    # extract the infected files
    infected_files = re.findall(r"\s+file\s+:\s+(.*)", threat_block)
    # write each infected file to the xml output
    for infected_file in infected_files:
        output += f"\t\t<infected_file>{infected_file.strip()}</infected_file>\n"

    # end the threat section in the xml output
    output += "\t</threat>\n"

# end the xml output
output += "</malware>"

# write the xml output to the output file
with open(output_file, "w") as f:
    f.write(output)

print(f"Conversion completed. Output saved in {output_file}")
