import re

# Read the current location.py file
with open('location.py', 'r') as f:
    content = f.read()

# Fix the formatting where 'location_name' and 'full_address' are on the same line
content = re.sub(r"('location_name':\s*'[^']+'),\s*('full_address')", r"\1,\n            \2", content)

# Write back to the file
with open('location.py', 'w') as f:
    f.write(content)

print("Fixed formatting issues!")
