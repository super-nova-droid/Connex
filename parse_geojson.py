import json
import re

# Read the GeoJSON file
with open('c:/Users/Alfredo/Downloads/CommunityClubs.geojson', 'r') as f:
    data = json.load(f)

centers = []
location_id = 1

for feature in data['features']:
    properties = feature['properties']
    geometry = feature['geometry']
    
    # Extract coordinates
    coords = geometry['coordinates']
    lng = coords[0]
    lat = coords[1]
    
    # Parse the HTML description to extract details
    description = properties['Description']
    
    # Extract name
    name_match = re.search(r'<th>NAME</th> <td>([^<]+)</td>', description)
    name = name_match.group(1) if name_match else 'Unknown'
    
    # Extract postal code
    postal_match = re.search(r'<th>ADDRESSPOSTALCODE</th> <td>([^<]+)</td>', description)
    postal_code = postal_match.group(1) if postal_match else ''
    
    # Extract street name
    street_match = re.search(r'<th>ADDRESSSTREETNAME</th> <td>([^<]+)</td>', description)
    street_name = street_match.group(1) if street_match else ''
    
    # Extract block/house number
    block_match = re.search(r'<th>ADDRESSBLOCKHOUSENUMBER</th> <td>([^<]+)</td>', description)
    block_number = block_match.group(1) if block_match else ''
    
    # Extract unit number
    unit_match = re.search(r'<th>ADDRESSUNITNUMBER</th> <td>([^<]+)</td>', description)
    unit_number = unit_match.group(1) if unit_match else ''
    
    # Skip PAssion WaVe centers (sea sports clubs)
    if 'PAssion WaVe' in name or 'Sea Sports Club' in name:
        continue
    
    # Clean up name
    name = name.replace(' (Pending U/C)', '').replace(' (U/C)', '')
    if name == 'imPAct@Hong Lim Green':
        name = 'Telok Ayer Hong Lim Green Community Centre'
    
    # Build full address
    address_parts = []
    if block_number:
        address_parts.append(block_number)
    if unit_number and unit_number != block_number:
        address_parts.append(f'#{unit_number}')
    if street_name:
        address_parts.append(street_name)
    if postal_code:
        address_parts.append(f'Singapore {postal_code}')
    
    full_address = ' '.join(address_parts)
    
    # Extract short name for address field
    if 'CC' in name:
        short_name = name.replace(' CC', '').replace(' Community Centre', '')
    else:
        short_name = name.replace(' Community Centre', '').replace(' Community Club', '')
    
    centers.append({
        'location_id': location_id,
        'location_name': name,
        'address': short_name,
        'full_address': full_address,
        'lat': lat,
        'lng': lng
    })
    
    location_id += 1

# Sort alphabetically by name
centers.sort(key=lambda x: x['location_name'])

# Print the result
print('Centers found:', len(centers))
for i, center in enumerate(centers):
    center['location_id'] = i + 1
    print(f"        {{")
    print(f"            'location_id': {center['location_id']},")
    print(f"            'location_name': '{center['location_name']}',")
    print(f"            'address': '{center['address']}',")
    print(f"            'full_address': '{center['full_address']}',")
    print(f"            'lat': {center['lat']:.6f},")
    print(f"            'lng': {center['lng']:.6f}")
    print(f"        }},")
