"""
Event Images Module for Connex Application
Handles storing and retrieving event images in the database
"""

import cv2
import numpy as np
import mysql.connector
import base64
from PIL import Image
import io


def get_db_connection():
    """Get database connection - should be imported from main app"""
    from app import get_db_connection as app_get_db_connection
    return app_get_db_connection()

def get_image_mime_type(image):
    """
    Get the MIME type of the image (e.g., image/jpeg, image/png)
    :param image: OpenCV image (numpy array)
    :return: MIME type string
    """
    try:
        # Convert OpenCV image (numpy array) to a byte stream
        _, buffer = cv2.imencode('.jpg', image)
        img_bytes = buffer.tobytes()
        
        # Use PIL to detect the MIME type
        img = Image.open(io.BytesIO(img_bytes))
        mime_type = img.format.lower()
        if mime_type == 'jpeg':
            return 'image/jpeg'
        elif mime_type == 'png':
            return 'image/png'
        elif mime_type == 'gif':
            return 'image/gif'
        return 'application/octet-stream'  # default if type can't be determined
    except Exception as e:
        print(f"Error detecting MIME type: {e}")
        return 'application/octet-stream'
    
def encode_image_to_blob(image):
    """
    Encode OpenCV image to binary BLOB format for database storage
    :param image: OpenCV image (numpy array)
    :return: binary data for BLOB storage
    """
    try:
        _, buffer = cv2.imencode('.jpg', image)
        return buffer.tobytes()
    except Exception as e:
        print(f"Error encoding image to BLOB: {e}")
        return None

def decode_blob_to_image(blob_data):
    """
    Decode binary BLOB data to OpenCV image
    :param blob_data: binary BLOB data
    :return: OpenCV image (numpy array)
    """
    try:
        nparr = np.frombuffer(blob_data, np.uint8)
        image = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        return image
    except Exception as e:
        print(f"Error decoding BLOB to image: {e}")
        return None

def store_event_image(event_id, image):
    """
    Store an image for an event in the Events table with MIME type
    :param event_id: ID of the event
    :param image: OpenCV image to store
    :return: Boolean indicating success
    """
    try:
        # Encode image to BLOB
        blob = encode_image_to_blob(image)
        if blob is None:
            return False, "Error encoding image"

        # Get MIME type
        mime_type = get_image_mime_type(image)

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE Events
            SET event_image = %s, event_image_mime = %s
            WHERE event_id = %s
        """, (blob, mime_type, event_id))

        if cursor.rowcount == 0:
            cursor.close()
            conn.close()
            return False, "Event not found"

        conn.commit()
        cursor.close()
        conn.close()
        print(f"Event image stored successfully for event {event_id}")
        return True, "Image stored successfully"

    except mysql.connector.Error as err:
        print(f"Database error storing event image: {err}")
        return False, f"Database error: {err}"
    except Exception as e:
        print(f"Error storing event image: {e}")
        return False, f"Error: {e}"


def get_event_image(event_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        query = "SELECT event_image FROM Events WHERE event_id = %s"
        cursor.execute(query, (event_id,))
        event = cursor.fetchone()
        
        if event and 'event_image' in event:
            return event['event_image'] # <-- THIS LINE IS THE FIX
        return None
    except Exception as e:
        print(f"Error fetching event image: {e}")
        return None
    finally:
        if 'conn' in locals() and conn.is_connected():
            cursor.close()
            conn.close()

def resize_image(image, width, height):
    """
    Resize an image to the given width and height
    :param image: OpenCV image
    :param width: target width
    :param height: target height
    :return: resized OpenCV image
    """
    try:
        return cv2.resize(image, (width, height))
    except Exception as e:
        print(f"Error resizing image: {e}")
        return image
    
def get_event_image_base64(event_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT event_image, event_image_mime FROM Events WHERE event_id = %s", (event_id,))
        result = cursor.fetchone()
        cursor.close()
        conn.close()

        if result and result[0]:
            image_blob = result[0]
            mime_type = result[1] if result[1] else 'image/jpeg'  # default to image/jpeg if MIME type is not found
            return f"data:{mime_type};base64," + base64.b64encode(image_blob).decode('utf-8')
        return None
    except Exception as e:
        print(f"Error retrieving image: {e}")
        return None



# Module initialization message
if __name__ != "__main__":
    print("Event Images Module loaded - using Events.event_image BLOB column")

# Testing
if __name__ == "__main__":
    print("Event Images Module - Test Mode")
    test_img = cv2.imread("test_event.jpg")  # Rep
