"""
Facial Recognition Module for Connex Application
Handles face registration, verification, and authentication for users
"""

import os
import cv2
import numpy as np
import mysql.connector
from flask import session, flash
import threading
import base64
import io
from PIL import Image

# Global variables
face_match = False
similarity_threshold = 0.6  # Template matching threshold

# Load face detection cascade
face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')

def get_db_connection():
    """Get database connection - should be imported from main app"""
    from app import get_db_connection as app_get_db_connection
    return app_get_db_connection()

def extract_face(image):
    """
    Extract the largest face from an image using OpenCV's face detection.
    :param image: Input image (numpy array)
    :return: Cropped face image or None if no face found
    """
    try:
        # Handle different image formats
        if isinstance(image, str):
            # If it's a file path
            image = cv2.imread(image)
        elif isinstance(image, bytes):
            # If it's binary data
            nparr = np.frombuffer(image, np.uint8)
            image = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        
        if image is None:
            return None
            
        gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
        faces = face_cascade.detectMultiScale(gray, scaleFactor=1.1, minNeighbors=5, minSize=(30, 30))
        
        if len(faces) == 0:
            return None
        
        # Get the largest face
        largest_face = max(faces, key=lambda rect: rect[2] * rect[3])
        x, y, w, h = largest_face
        
        # Extract and resize face
        face = image[y:y+h, x:x+w]
        face_resized = cv2.resize(face, (100, 100))  # Standardize size
        
        return face_resized
        
    except Exception as e:
        print(f"Error extracting face: {e}")
        return None

def compare_faces(face1, face2):
    """
    Compare two face images using template matching.
    :param face1: First face image
    :param face2: Second face image
    :return: Similarity score (0-1)
    """
    if face1 is None or face2 is None:
        return 0.0
    
    try:
        # Convert to grayscale
        gray1 = cv2.cvtColor(face1, cv2.COLOR_BGR2GRAY)
        gray2 = cv2.cvtColor(face2, cv2.COLOR_BGR2GRAY)
        
        # Resize to same size
        gray1 = cv2.resize(gray1, (100, 100))
        gray2 = cv2.resize(gray2, (100, 100))
        
        # Template matching
        result = cv2.matchTemplate(gray1, gray2, cv2.TM_CCOEFF_NORMED)
        similarity = result[0][0]
        
        return similarity
    except Exception as e:
        print(f"Error comparing faces: {e}")
        return 0.0

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

def register_user_face(user_id, face_image):
    """
    Register a user's face in the Users table as BLOB
    :param user_id: User ID from the Users table
    :param face_image: OpenCV image of the user's face
    :return: Boolean indicating success
    """
    try:
        # Extract face from the image
        face = extract_face(face_image)
        if face is None:
            return False, "No face detected in the image"
        
        # Encode face to BLOB format
        face_blob = encode_image_to_blob(face)
        if face_blob is None:
            return False, "Error processing face image"
        
        # Store in Users table
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Update the facial_image column in Users table
        cursor.execute("""
            UPDATE Users 
            SET facial_image = %s 
            WHERE user_id = %s
        """, (face_blob, user_id))
        
        if cursor.rowcount == 0:
            cursor.close()
            conn.close()
            return False, "User not found"
        
        conn.commit()
        cursor.close()
        conn.close()
        
        print(f"Face registered successfully for user {user_id} in Users table")
        return True, "Face registered successfully"
        
    except mysql.connector.Error as err:
        print(f"Database error registering face: {err}")
        return False, f"Database error: {err}"
    except Exception as e:
        print(f"Error registering face: {e}")
        return False, f"Error: {e}"

def verify_user_face(user_id, face_image):
    """
    Verify a user's face against their registered face in Users table
    :param user_id: User ID from the Users table
    :param face_image: OpenCV image to verify
    :return: Boolean indicating if face matches
    """
    try:
        # Extract face from the provided image
        current_face = extract_face(face_image)
        if current_face is None:
            return False, "No face detected in the image"
        
        # Get registered face from Users table
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT facial_image FROM Users WHERE user_id = %s", (user_id,))
        result = cursor.fetchone()
        
        cursor.close()
        conn.close()
        
        if not result or result[0] is None:
            return False, "No registered face found for user"
        
        # Decode registered face from BLOB
        registered_face = decode_blob_to_image(result[0])
        if registered_face is None:
            return False, "Error loading registered face"
        
        # Compare faces
        similarity = compare_faces(registered_face, current_face)
        is_match = similarity >= similarity_threshold
        
        # Enhanced debugging output
        print(f"--- FACE COMPARISON DETAILS ---")
        print(f"Similarity Score: {similarity:.4f}")
        print(f"Required Threshold: {similarity_threshold}")
        print(f"Result: {'MATCH' if is_match else 'NO MATCH'}")
        print(f"Status: {'✓ ACCEPTED' if is_match else '✗ REJECTED'}")
        
        if is_match:
            return True, f"Face verified (similarity: {similarity:.4f})"
        else:
            return False, f"Face does not match (similarity: {similarity:.4f}, threshold: {similarity_threshold})"
        
    except mysql.connector.Error as err:
        print(f"Database error during face verification: {err}")
        return False, f"Database error: {err}"
    except Exception as e:
        print(f"Error during face verification: {e}")
        return False, f"Error: {e}"

def capture_face_from_webcam():
    """
    Capture a face image from the webcam with countdown
    :return: OpenCV image or None if capture failed
    """
    try:
        print("Starting webcam capture for face registration...")
        
        # Initialize the webcam
        cap = cv2.VideoCapture(0, cv2.CAP_DSHOW)
        cap.set(cv2.CAP_PROP_FRAME_WIDTH, 640)
        cap.set(cv2.CAP_PROP_FRAME_HEIGHT, 480)
        
        if not cap.isOpened():
            print("Error: Could not open webcam.")
            return None
        
        countdown = 5
        start_time = cv2.getTickCount()
        captured_image = None
        
        while countdown > 0:
            ret, frame = cap.read()
            if not ret:
                print("Error: Unable to read from webcam.")
                cap.release()
                return None
            
            # Calculate elapsed time
            current_time = cv2.getTickCount()
            elapsed = (current_time - start_time) / cv2.getTickFrequency()
            
            if elapsed >= 1.0:  # One second has passed
                countdown -= 1
                start_time = current_time
                print(f"Capturing face in {countdown} seconds...")
            
            # Draw countdown on frame
            cv2.putText(frame, f"Face Capture: {countdown}", (50, 50), 
                       cv2.FONT_HERSHEY_SIMPLEX, 1, (0, 255, 255), 2)
            cv2.putText(frame, "Position your face in the center", (50, 100), 
                       cv2.FONT_HERSHEY_SIMPLEX, 0.7, (255, 255, 255), 2)
            
            # Draw face detection rectangles
            gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
            faces = face_cascade.detectMultiScale(gray, scaleFactor=1.1, minNeighbors=5, minSize=(30, 30))
            
            for (x, y, w, h) in faces:
                cv2.rectangle(frame, (x, y), (x+w, y+h), (0, 255, 0), 2)
            
            cv2.imshow("Face Registration", frame)
            
            # Allow early exit with 'q'
            if cv2.waitKey(1) & 0xFF == ord('q'):
                print("Face capture cancelled.")
                cap.release()
                cv2.destroyAllWindows()
                return None
        
        # Capture the final frame
        ret, captured_image = cap.read()
        cap.release()
        cv2.destroyAllWindows()
        
        if not ret:
            print("Error: Could not capture final frame.")
            return None
        
        print("Face captured successfully!")
        return captured_image
        
    except Exception as e:
        print(f"Error during webcam capture: {e}")
        return None

def check_user_has_face(user_id):
    """
    Check if a user has a registered face image
    :param user_id: User ID
    :return: Boolean indicating if user has face registered
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT facial_image FROM Users WHERE user_id = %s", (user_id,))
        result = cursor.fetchone()
        
        cursor.close()
        conn.close()
        
        return result and result[0] is not None
        
    except Exception as e:
        print(f"Error checking if user has face: {e}")
        return False

def check_face_recognition_enabled(user_id):
    """
    Check if facial recognition is enabled for a user (now checks if facial_image exists)
    :param user_id: User ID
    :return: Boolean indicating if facial recognition is enabled
    """
    return check_user_has_face(user_id)

def enable_facial_recognition(user_id):
    """
    Enable facial recognition for a user (deprecated - now we just check if facial_image exists)
    :param user_id: User ID
    :return: Boolean indicating success
    """
    # Since we're using facial_image column, this function is no longer needed
    # Facial recognition is "enabled" if the user has a facial_image stored
    return check_user_has_face(user_id)

def process_webcam_image_data(image_data):
    """
    Process base64 image data from webcam (for web-based capture)
    :param image_data: base64 encoded image string
    :return: OpenCV image or None
    """
    try:
        # Remove data URL prefix if present
        if ',' in image_data:
            image_data = image_data.split(',')[1]
        
        # Decode base64
        image_bytes = base64.b64decode(image_data)
        
        # Convert to PIL Image
        pil_image = Image.open(io.BytesIO(image_bytes))
        
        # Convert to OpenCV format
        opencv_image = cv2.cvtColor(np.array(pil_image), cv2.COLOR_RGB2BGR)
        
        return opencv_image
        
    except Exception as e:
        print(f"Error processing webcam image data: {e}")
        return None

# Module initialization - no separate table needed since we use Users.facial_image
if __name__ != "__main__":
    try:
        # Module loaded successfully
        print("Facial Recognition Module loaded - using Users.facial_image BLOB column")
    except Exception as e:
        print(f"Warning: Could not initialize facial recognition module: {e}")

# For testing purposes
if __name__ == "__main__":
    print("Facial Recognition Module - Test Mode")
    print("Using Users table facial_image BLOB column for face storage")
    
    # Test webcam capture
    test_image = capture_face_from_webcam()
    if test_image is not None:
        print("Webcam capture test successful!")
        cv2.imwrite("test_capture.jpg", test_image)
        print("Test image saved as 'test_capture.jpg'")
        
        # Test face extraction
        face = extract_face(test_image)
        if face is not None:
            print("Face extraction test successful!")
            cv2.imwrite("test_face.jpg", face)
            print("Extracted face saved as 'test_face.jpg'")
        else:
            print("Face extraction test failed - no face detected")
    else:
        print("Webcam capture test failed.")
