import re

# Read the current location.py file
with open('location.py', 'r') as f:
    content = f.read()

# Function to update each center entry
def update_center_entry(match):
    entry = match.group(0)
    
    # Remove the 'address' line
    entry = re.sub(r"\s*'address':\s*'[^']*',\s*\n", "", entry)
    
    # Replace CC with Community Center in location_name
    entry = re.sub(r"'location_name':\s*'([^']*)\sCC'", r"'location_name': '\1 Community Center'", entry)
    
    return entry

# Pattern to match each community center entry
pattern = r"{\s*'location_id':\s*\d+,\s*'location_name':[^}]+}"

# Update all entries
updated_content = re.sub(pattern, update_center_entry, content, flags=re.DOTALL)

# Write back to the file
with open('location.py', 'w') as f:
    f.write(updated_content)

print("Successfully updated all community center entries!")
