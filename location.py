import os
import googlemaps
from flask import current_app

def get_google_maps_client():
    """Initialize Google Maps client with API key"""
    api_key = os.environ.get('GOOGLE_MAPS_API_KEY')
    if not api_key:
        print("WARNING: GOOGLE_MAPS_API_KEY not found in environment variables")
        return None
    try:
        return googlemaps.Client(key=api_key)
    except Exception as e:
        print(f"WARNING: Failed to initialize Google Maps client: {e}")
        return None

def get_community_centers():
    """Return list of community centers with their coordinates"""
    return [
        {
            'location_id': 1,
            'location_name': 'Hougang Community Centre',
            'address': 'Hougang',
            'full_address': '35 Hougang Ave 3, Singapore 538840',
            'lat': 1.3614,
            'lng': 103.8937
        },
        {
            'location_id': 2,
            'location_name': 'Seng Kang Community Centre',
            'address': 'Seng Kang',
            'full_address': '2 Sengkang Square, Singapore 545025',
            'lat': 1.3917,
            'lng': 103.8951
        },
        {
            'location_id': 3,
            'location_name': 'Punggol Community Centre',
            'address': 'Punggol',
            'full_address': '24 Punggol Field Walk, Singapore 828816',
            'lat': 1.4043,
            'lng': 103.9058
        },
        {
            'location_id': 4,
            'location_name': 'Ang Mo Kio Community Centre',
            'address': 'Ang Mo Kio',
            'full_address': '721 Ang Mo Kio Ave 8, Singapore 560721',
            'lat': 1.3691,
            'lng': 103.8454
        },
        {
            'location_id': 5,
            'location_name': 'Bishan Community Centre',
            'address': 'Bishan',
            'full_address': '51 Bishan St 13, Singapore 579799',
            'lat': 1.3506,
            'lng': 103.8480
        }
    ]

def find_closest_community_center(user_lat, user_lng):
    """
    Find the closest community center to user's location
    Falls back to simple distance calculation if Google Maps API is not available
    """
    try:
        gmaps = get_google_maps_client()
        community_centers = get_community_centers()
        
        if gmaps:
            # Try to use Google Maps Distance Matrix API
            user_location = (user_lat, user_lng)
            destinations = [(center['lat'], center['lng']) for center in community_centers]
            
            try:
                matrix = gmaps.distance_matrix(
                    origins=[user_location],
                    destinations=destinations,
                    mode="driving",
                    units="metric",
                    avoid="tolls"
                )
                
                if matrix['status'] == 'OK':
                    # Find the center with minimum distance
                    min_distance = float('inf')
                    closest_center = None
                    
                    for i, element in enumerate(matrix['rows'][0]['elements']):
                        if element['status'] == 'OK':
                            distance = element['distance']['value']  # Distance in meters
                            if distance < min_distance:
                                min_distance = distance
                                closest_center = community_centers[i].copy()
                                closest_center['distance'] = element['distance']['text']
                                closest_center['duration'] = element['duration']['text']
                    
                    if closest_center:
                        return closest_center
            except Exception as api_error:
                print(f"Google Maps API error, falling back to simple calculation: {api_error}")
        
        # Fallback: Use simple Euclidean distance calculation
        print("Using fallback distance calculation (no Google Maps API)")
        min_distance = float('inf')
        closest_center = None
        
        for center in community_centers:
            # Calculate simple distance (not accurate but works as fallback)
            distance = ((user_lat - center['lat']) ** 2 + (user_lng - center['lng']) ** 2) ** 0.5
            if distance < min_distance:
                min_distance = distance
                closest_center = center.copy()
                closest_center['distance'] = f"~{distance * 111:.1f} km"  # Rough conversion
                closest_center['duration'] = "N/A"
        
        return closest_center
        
    except Exception as e:
        print(f"Error finding closest community center: {e}")
        # Return first center as ultimate fallback
        centers = get_community_centers()
        if centers:
            fallback = centers[0].copy()
            fallback['distance'] = "N/A"
            fallback['duration'] = "N/A"
            return fallback
        return None

def geocode_address(address):
    """
    Convert address to coordinates using Google Geocoding API
    Returns None if API is not available
    """
    try:
        gmaps = get_google_maps_client()
        if not gmaps:
            print("Google Maps API not available for geocoding")
            return None
        
        geocode_result = gmaps.geocode(address)
        
        if geocode_result:
            location = geocode_result[0]['geometry']['location']
            return {
                'lat': location['lat'],
                'lng': location['lng'],
                'formatted_address': geocode_result[0]['formatted_address']
            }
        
        return None
        
    except Exception as e:
        print(f"Error geocoding address: {e}")
        return None
