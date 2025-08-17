# ================================================================================================
# SERVER-SIDE VALIDATION MODULE FOR CONNEX APPLICATION
# ================================================================================================
# This module provides comprehensive server-side validation for all authentication-related
# features in the Connex application. These validations work alongside client-side validation
# to ensure data integrity and security.
#
# VALIDATION CATEGORIES:
# 1. LOGIN VALIDATION - Email/username and password validation for login attempts
# 2. SIGNUP VALIDATION - Complete user registration data validation
# 3. SECURITY QUESTIONS VALIDATION - Security question setup and verification
# 4. FACIAL RECOGNITION VALIDATION - Face image data and facial recognition validation
# 5. OTP VALIDATION - One-time password validation for email verification
# 6. SESSION VALIDATION - Session data integrity and security validation
# ================================================================================================

import re
import base64
import cv2
import numpy as np
from datetime import datetime, date, timedelta
from werkzeug.security import check_password_hash
import mysql.connector
from typing import Tuple, Optional, Dict, Any, List

# ================================================================================================
# LOGIN VALIDATION FUNCTIONS
# ================================================================================================
# These functions validate login attempts including email/username format validation,
# password strength verification, and credential authentication.

def validate_login_credentials(email_or_username: str, password: str) -> Tuple[bool, str]:
    """
    SERVER-SIDE VALIDATION: Login credentials validation
    
    Validates user login input including email/username format and password requirements.
    This validation runs on the server to prevent malicious data submission.
    
    Args:
        email_or_username (str): User's email or username input
        password (str): User's password input
    
    Returns:
        Tuple[bool, str]: (is_valid, error_message)
    """
    # Validate email_or_username is not empty and within reasonable length
    if not email_or_username or not email_or_username.strip():
        return False, "Email or username is required"
    
    email_or_username = email_or_username.strip()
    
    # Check length constraints (prevent buffer overflow attacks)
    if len(email_or_username) > 255:
        return False, "Email or username is too long"
    
    if len(email_or_username) < 3:
        return False, "Email or username must be at least 3 characters"
    
    # Validate password is not empty
    if not password:
        return False, "Password is required"
    
    # Check password length constraints
    if len(password) > 1000:  # Prevent potential DoS attacks with extremely long passwords
        return False, "Password is too long"
    
    # Check for suspicious characters that might indicate injection attempts
    suspicious_patterns = [
        r'<script',  # XSS attempts
        r'javascript:',  # JavaScript injection
        r'data:',  # Data URI injection
        r'vbscript:',  # VBScript injection
        r'onload=',  # Event handler injection
        r'onerror=',  # Event handler injection
    ]
    
    for pattern in suspicious_patterns:
        if re.search(pattern, email_or_username, re.IGNORECASE):
            return False, "Invalid characters detected in email or username"
    
    # If it looks like an email, validate email format
    if '@' in email_or_username:
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, email_or_username):
            return False, "Invalid email format"
    
    return True, "Valid login credentials"

def validate_user_exists_and_active(user_data: Optional[Dict]) -> Tuple[bool, str]:
    """
    SERVER-SIDE VALIDATION: User existence and account status validation
    
    Validates that user exists in database and account is active (not deleted or suspended).
    
    Args:
        user_data (Optional[Dict]): User data from database query
    
    Returns:
        Tuple[bool, str]: (is_valid, error_message)
    """
    if not user_data:
        return False, "Invalid credentials"  # Generic message to prevent user enumeration
    
    # Check if account is marked as deleted
    if user_data.get('is_deleted', 0) == 1:
        return False, "Account not found"  # Generic message to prevent user enumeration
    
    # Check if account is suspended (if you have this field)
    if user_data.get('is_suspended', 0) == 1:
        return False, "Account access restricted"
    
    return True, "User account is valid and active"

# ================================================================================================
# SIGNUP VALIDATION FUNCTIONS
# ================================================================================================
# These functions validate user registration data including username uniqueness,
# email format, password complexity, and personal information.

def validate_signup_username(username: str, existing_usernames: List[str] = None) -> Tuple[bool, str]:
    """
    SERVER-SIDE VALIDATION: Username validation for signup
    
    Validates username format, length, character restrictions, and uniqueness.
    
    Args:
        username (str): Proposed username
        existing_usernames (List[str], optional): List of existing usernames to check against
    
    Returns:
        Tuple[bool, str]: (is_valid, error_message)
    """
    if not username or not username.strip():
        return False, "Username is required"
    
    username = username.strip()
    
    # Length validation
    if len(username) < 3:
        return False, "Username must be at least 3 characters long"
    
    if len(username) > 50:
        return False, "Username cannot exceed 50 characters"
    
    # Character validation - allow letters, numbers, underscores, hyphens, dots
    if not re.match(r'^[a-zA-Z0-9._-]+$', username):
        return False, "Username can only contain letters, numbers, underscores, hyphens, and dots"
    
    # Must start with letter or number
    if not re.match(r'^[a-zA-Z0-9]', username):
        return False, "Username must start with a letter or number"
    
    # Cannot end with special characters
    if username.endswith(('.', '_', '-')):
        return False, "Username cannot end with special characters"
    
    # Check for consecutive special characters
    if re.search(r'[._-]{2,}', username):
        return False, "Username cannot contain consecutive special characters"
    
    # Reserved usernames
    reserved_usernames = [
        'admin', 'administrator', 'root', 'system', 'user', 'test', 'demo',
        'null', 'undefined', 'api', 'www', 'mail', 'email', 'support',
        'help', 'info', 'contact', 'about', 'login', 'signup', 'register'
    ]
    
    if username.lower() in reserved_usernames:
        return False, "This username is reserved and cannot be used"
    
    # Check uniqueness if existing usernames provided
    if existing_usernames and username.lower() in [u.lower() for u in existing_usernames]:
        return False, "Username is already taken"
    
    return True, "Username is valid"

def validate_signup_email(email: str, existing_emails: List[str] = None) -> Tuple[bool, str]:
    """
    SERVER-SIDE VALIDATION: Email validation for signup
    
    Validates email format, domain restrictions, and uniqueness.
    
    Args:
        email (str): Email address to validate
        existing_emails (List[str], optional): List of existing emails to check against
    
    Returns:
        Tuple[bool, str]: (is_valid, error_message)
    """
    # Email is optional in the system, so empty email is valid
    if not email or not email.strip():
        return True, "Email validation passed (optional field)"
    
    email = email.strip().lower()
    
    # Length validation
    if len(email) > 255:
        return False, "Email address is too long"
    
    # Basic email format validation
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_pattern, email):
        return False, "Invalid email format"
    
    # Additional email validation rules
    local_part, domain = email.split('@', 1)
    
    # Local part validation
    if len(local_part) > 64:
        return False, "Email local part is too long"
    
    if local_part.startswith('.') or local_part.endswith('.'):
        return False, "Email cannot start or end with a dot"
    
    if '..' in local_part:
        return False, "Email cannot contain consecutive dots"
    
    # Domain validation
    if len(domain) > 255:
        return False, "Email domain is too long"
    
    # Check for valid domain format
    domain_parts = domain.split('.')
    for part in domain_parts:
        if not part:
            return False, "Invalid domain format"
        if not re.match(r'^[a-zA-Z0-9-]+$', part):
            return False, "Invalid characters in domain"
        if part.startswith('-') or part.endswith('-'):
            return False, "Domain parts cannot start or end with hyphen"
    
    # Blocked domains (spam/temporary email services)
    blocked_domains = [
        '10minutemail.com', 'guerrillamail.com', 'mailinator.com',
        'tempmail.org', 'throwaway.email', 'temp-mail.org'
    ]
    
    if domain in blocked_domains:
        return False, "Temporary email addresses are not allowed"
    
    # Check uniqueness if existing emails provided
    if existing_emails and email in [e.lower() for e in existing_emails]:
        return False, "Email address is already registered"
    
    return True, "Email is valid"

def validate_signup_password(password: str, confirm_password: str) -> Tuple[bool, str]:
    """
    SERVER-SIDE VALIDATION: Password validation for signup
    
    Validates password complexity, strength, and confirmation match.
    
    Args:
        password (str): Primary password
        confirm_password (str): Password confirmation
    
    Returns:
        Tuple[bool, str]: (is_valid, error_message)
    """
    if not password:
        return False, "Password is required"
    
    # Length validation
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    
    if len(password) > 1000:
        return False, "Password is too long"
    
    # Complexity requirements
    has_upper = bool(re.search(r'[A-Z]', password))
    has_lower = bool(re.search(r'[a-z]', password))
    has_digit = bool(re.search(r'[0-9]', password))
    has_special = bool(re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]', password))
    
    if not has_upper:
        return False, "Password must contain at least one uppercase letter"
    
    if not has_lower:
        return False, "Password must contain at least one lowercase letter"
    
    if not has_digit:
        return False, "Password must contain at least one number"
    
    if not has_special:
        return False, "Password must contain at least one special character"
    
    # Check for common weak patterns
    weak_patterns = [
        r'password', r'123456', r'qwerty', r'abc123', r'admin',
        r'letmein', r'welcome', r'monkey', r'dragon'
    ]
    
    for pattern in weak_patterns:
        if re.search(pattern, password, re.IGNORECASE):
            return False, "Password contains common weak patterns"
    
    # Check for sequential characters
    if re.search(r'(012|123|234|345|456|567|678|789|890|abc|bcd|cde|def)', password, re.IGNORECASE):
        return False, "Password cannot contain sequential characters"
    
    # Confirmation match validation
    if password != confirm_password:
        return False, "Passwords do not match"
    
    return True, "Password is valid and secure"

def validate_date_of_birth_server(dob_str: str) -> Tuple[bool, str]:
    """
    SERVER-SIDE VALIDATION: Date of birth validation
    
    Validates date format, reasonable age ranges, and business logic constraints.
    
    Args:
        dob_str (str): Date of birth string in YYYY-MM-DD format
    
    Returns:
        Tuple[bool, str]: (is_valid, error_message)
    """
    if not dob_str or not dob_str.strip():
        return False, "Date of birth is required"
    
    dob_str = dob_str.strip()
    
    # Date format validation
    try:
        dob = datetime.strptime(dob_str, '%Y-%m-%d').date()
    except ValueError:
        return False, "Invalid date format. Use YYYY-MM-DD"
    
    today = date.today()
    
    # Future date validation
    if dob > today:
        return False, "Date of birth cannot be in the future"
    
    # Calculate age
    age = today.year - dob.year - ((today.month, today.day) < (dob.month, dob.day))
    
    # Minimum age validation (for legal compliance)
    if age < 13:
        return False, "You must be at least 13 years old to register"
    
    # Maximum age validation (reasonable check)
    if age > 120:
        return False, "Please enter a valid date of birth"
    
    # Check for obviously fake dates
    if dob.year < 1900:
        return False, "Date of birth must be after 1900"
    
    return True, "Date of birth is valid"

def validate_location_selection(location_id: str, valid_locations: List[Dict]) -> Tuple[bool, str]:
    """
    SERVER-SIDE VALIDATION: Community center location validation
    
    Validates that selected location exists and is valid.
    
    Args:
        location_id (str): Selected location ID
        valid_locations (List[Dict]): List of valid community center locations
    
    Returns:
        Tuple[bool, str]: (is_valid, error_message)
    """
    if not location_id or not location_id.strip():
        return False, "Please select a community centre"
    
    try:
        location_id_int = int(location_id.strip())
    except ValueError:
        return False, "Invalid location selection"
    
    # Check if location exists in valid locations
    valid_location_ids = [loc.get('location_id') for loc in valid_locations if loc.get('location_id')]
    
    if location_id_int not in valid_location_ids:
        return False, "Selected community centre is not valid"
    
    return True, "Location selection is valid"

# ================================================================================================
# SECURITY QUESTIONS VALIDATION FUNCTIONS
# ================================================================================================
# These functions validate security question setup and verification during authentication.

def validate_security_question_answers(question1: str, question2: str, question3: str) -> Tuple[bool, str]:
    """
    SERVER-SIDE VALIDATION: Security question answers validation
    
    Validates security question answers for completeness and reasonable content.
    
    Args:
        question1 (str): Answer to security question 1
        question2 (str): Answer to security question 2
        question3 (str): Answer to security question 3
    
    Returns:
        Tuple[bool, str]: (is_valid, error_message)
    """
    answers = [question1, question2, question3]
    
    for i, answer in enumerate(answers, 1):
        if not answer or not answer.strip():
            return False, f"Answer to question {i} is required"
        
        answer = answer.strip()
        
        # Length validation
        if len(answer) < 2:
            return False, f"Answer to question {i} is too short (minimum 2 characters)"
        
        if len(answer) > 100:
            return False, f"Answer to question {i} is too long (maximum 100 characters)"
        
        # Check for suspicious content
        if re.search(r'<script|javascript:|data:|vbscript:', answer, re.IGNORECASE):
            return False, f"Answer to question {i} contains invalid content"
        
        # Ensure answers are not all the same
        if i > 1 and answer.lower() == answers[0].strip().lower():
            return False, "All security question answers cannot be the same"
    
    return True, "Security question answers are valid"

def validate_security_question_verification(stored_answers: List[str], provided_answers: List[str]) -> Tuple[bool, str]:
    """
    SERVER-SIDE VALIDATION: Security question answer verification
    
    Validates provided answers against stored security question answers.
    
    Args:
        stored_answers (List[str]): Stored security question answers from database
        provided_answers (List[str]): User-provided answers for verification
    
    Returns:
        Tuple[bool, str]: (is_valid, error_message)
    """
    if len(stored_answers) != 3 or len(provided_answers) != 3:
        return False, "Invalid security question data"
    
    # Check if all stored answers exist
    for i, stored_answer in enumerate(stored_answers, 1):
        if not stored_answer or stored_answer.strip() == '' or stored_answer.lower() == 'null':
            return False, f"Security question {i} is not set up"
    
    # Validate provided answers format
    for i, provided_answer in enumerate(provided_answers, 1):
        if not provided_answer or not provided_answer.strip():
            return False, f"Answer to question {i} is required"
    
    # Compare answers (case-insensitive, trimmed)
    for i, (stored, provided) in enumerate(zip(stored_answers, provided_answers), 1):
        if stored.strip().lower() != provided.strip().lower():
            return False, "One or more security question answers are incorrect"
    
    return True, "Security question verification successful"

# ================================================================================================
# FACIAL RECOGNITION VALIDATION FUNCTIONS
# ================================================================================================
# These functions validate facial recognition data and image processing.

def validate_face_image_data(image_data: str) -> Tuple[bool, str, Optional[np.ndarray]]:
    """
    SERVER-SIDE VALIDATION: Facial recognition image data validation
    
    Validates base64 image data and converts to OpenCV format for face processing.
    
    Args:
        image_data (str): Base64 encoded image data from webcam
    
    Returns:
        Tuple[bool, str, Optional[np.ndarray]]: (is_valid, error_message, opencv_image)
    """
    if not image_data or not image_data.strip():
        return False, "No image data provided", None
    
    try:
        # Remove data URL prefix if present
        if image_data.startswith('data:image'):
            image_data = image_data.split(',')[1]
        
        # Validate base64 format
        try:
            image_bytes = base64.b64decode(image_data)
        except Exception:
            return False, "Invalid image data format", None
        
        # Check image size (prevent DoS attacks with huge images)
        if len(image_bytes) > 10 * 1024 * 1024:  # 10MB limit
            return False, "Image file is too large", None
        
        if len(image_bytes) < 1000:  # Minimum size check
            return False, "Image file is too small", None
        
        # Convert to OpenCV format
        nparr = np.frombuffer(image_bytes, np.uint8)
        opencv_image = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        
        if opencv_image is None:
            return False, "Could not process image data", None
        
        # Validate image dimensions
        height, width = opencv_image.shape[:2]
        
        if width < 100 or height < 100:
            return False, "Image resolution is too low (minimum 100x100)", None
        
        if width > 4000 or height > 4000:
            return False, "Image resolution is too high (maximum 4000x4000)", None
        
        # Check if image is not corrupted (basic validation)
        if opencv_image.size == 0:
            return False, "Image appears to be corrupted", None
        
        return True, "Image data is valid", opencv_image
        
    except Exception as e:
        return False, f"Error processing image data: {str(e)}", None

def validate_face_detection_result(opencv_image: np.ndarray) -> Tuple[bool, str]:
    """
    SERVER-SIDE VALIDATION: Face detection validation
    
    Validates that a proper face can be detected in the provided image.
    
    Args:
        opencv_image (np.ndarray): OpenCV image array
    
    Returns:
        Tuple[bool, str]: (is_valid, error_message)
    """
    try:
        # Load face detection cascade
        face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')
        
        if face_cascade.empty():
            return False, "Face detection system is not available"
        
        # Convert to grayscale for face detection
        gray = cv2.cvtColor(opencv_image, cv2.COLOR_BGR2GRAY)
        
        # Detect faces
        faces = face_cascade.detectMultiScale(
            gray,
            scaleFactor=1.1,
            minNeighbors=5,
            minSize=(30, 30)
        )
        
        if len(faces) == 0:
            return False, "No face detected in the image. Please ensure your face is clearly visible and well-lit."
        
        # Use the largest face if multiple faces are detected
        largest_face = max(faces, key=lambda rect: rect[2] * rect[3])
        face_x, face_y, face_w, face_h = largest_face
        
        if face_w < 80 or face_h < 80:
            return False, "Detected face is too small. Please move closer to the camera."
        
        # Check if face takes up reasonable portion of image
        image_area = opencv_image.shape[0] * opencv_image.shape[1]
        face_area = face_w * face_h
        face_ratio = face_area / image_area
        
        if face_ratio < 0.02:  # Face should be at least 2% of image
            return False, "Face is too small in the image. Please move closer to the camera."
        
        if face_ratio > 0.8:  # Face shouldn't be more than 80% of image
            return False, "Face is too close to the camera. Please move back slightly."
        
        return True, "Face detection successful"
        
    except Exception as e:
        return False, f"Error during face detection: {str(e)}"

# ================================================================================================
# OTP VALIDATION FUNCTIONS
# ================================================================================================
# These functions validate one-time passwords for email verification.

def validate_otp_input(provided_otp: str, stored_otp: str, otp_timestamp: Optional[datetime] = None) -> Tuple[bool, str]:
    """
    SERVER-SIDE VALIDATION: OTP validation
    
    Validates OTP format, expiry, and correctness.
    
    Args:
        provided_otp (str): OTP provided by user
        stored_otp (str): OTP stored in session/database
        otp_timestamp (Optional[datetime]): When OTP was generated (for expiry check)
    
    Returns:
        Tuple[bool, str]: (is_valid, error_message)
    """
    if not provided_otp or not provided_otp.strip():
        return False, "OTP is required"
    
    if not stored_otp or not stored_otp.strip():
        return False, "No OTP found in session. Please request a new OTP."
    
    provided_otp = provided_otp.strip()
    stored_otp = stored_otp.strip()
    
    # Format validation - should be 6 digits
    if not re.match(r'^\d{6}$', provided_otp):
        return False, "OTP must be exactly 6 digits"
    
    # Check expiry if timestamp provided (OTP valid for 10 minutes)
    if otp_timestamp:
        current_time = datetime.now()
        if current_time - otp_timestamp > timedelta(minutes=10):
            return False, "OTP has expired. Please request a new one."
    
    # Compare OTPs
    if provided_otp != stored_otp:
        return False, "Invalid OTP. Please check and try again."
    
    return True, "OTP is valid"

# ================================================================================================
# SESSION VALIDATION FUNCTIONS
# ================================================================================================
# These functions validate session data integrity and security.

def validate_session_data(session_data: Dict[str, Any], required_fields: List[str]) -> Tuple[bool, str]:
    """
    SERVER-SIDE VALIDATION: Session data validation
    
    Validates that required session data exists and is properly formatted.
    
    Args:
        session_data (Dict[str, Any]): Session data dictionary
        required_fields (List[str]): List of required field names
    
    Returns:
        Tuple[bool, str]: (is_valid, error_message)
    """
    if not session_data:
        return False, "No session data found"
    
    # Check for required fields
    for field in required_fields:
        if field not in session_data:
            return False, f"Missing required session field: {field}"
        
        if session_data[field] is None:
            return False, f"Session field {field} is null"
    
    # Validate session expiry if present
    if 'expires' in session_data:
        try:
            expires_timestamp = float(session_data['expires'])
            current_timestamp = datetime.now().timestamp()
            
            if current_timestamp > expires_timestamp:
                return False, "Session has expired"
        except (ValueError, TypeError):
            return False, "Invalid session expiry data"
    
    return True, "Session data is valid"

def validate_user_role(role: str, allowed_roles: List[str]) -> Tuple[bool, str]:
    """
    SERVER-SIDE VALIDATION: User role validation
    
    Validates user role against allowed roles for specific operations.
    
    Args:
        role (str): User's role
        allowed_roles (List[str]): List of allowed roles
    
    Returns:
        Tuple[bool, str]: (is_valid, error_message)
    """
    if not role or not role.strip():
        return False, "User role is not set"
    
    role = role.strip().lower()
    allowed_roles_lower = [r.lower() for r in allowed_roles]
    
    if role not in allowed_roles_lower:
        return False, f"Access denied. Required role: {', '.join(allowed_roles)}"
    
    return True, "User role is authorized"

# ================================================================================================
# UTILITY VALIDATION FUNCTIONS
# ================================================================================================
# General utility functions for common validation tasks.

def validate_csrf_token(provided_token: str, session_token: str) -> Tuple[bool, str]:
    """
    SERVER-SIDE VALIDATION: CSRF token validation
    
    Validates CSRF token to prevent cross-site request forgery attacks.
    
    Args:
        provided_token (str): CSRF token from form/request
        session_token (str): CSRF token from session
    
    Returns:
        Tuple[bool, str]: (is_valid, error_message)
    """
    if not provided_token or not session_token:
        return False, "CSRF token validation failed"
    
    if provided_token != session_token:
        return False, "CSRF token mismatch"
    
    return True, "CSRF token is valid"

def sanitize_input(input_data: str, max_length: int = 1000) -> str:
    """
    SERVER-SIDE VALIDATION: Input sanitization
    
    Sanitizes user input to prevent XSS and injection attacks.
    
    Args:
        input_data (str): Raw input data
        max_length (int): Maximum allowed length
    
    Returns:
        str: Sanitized input data
    """
    if not input_data:
        return ""
    
    # Trim whitespace
    sanitized = input_data.strip()
    
    # Truncate if too long
    if len(sanitized) > max_length:
        sanitized = sanitized[:max_length]
    
    # Remove potentially dangerous characters/patterns
    dangerous_patterns = [
        r'<script.*?</script>',
        r'javascript:',
        r'vbscript:',
        r'data:',
        r'onload=',
        r'onerror=',
        r'onclick=',
        r'onmouseover=',
    ]
    
    for pattern in dangerous_patterns:
        sanitized = re.sub(pattern, '', sanitized, flags=re.IGNORECASE | re.DOTALL)
    
    return sanitized

def validate_request_rate_limit(user_id: str, action: str, time_window: int = 60, max_attempts: int = 5) -> Tuple[bool, str]:
    """
    SERVER-SIDE VALIDATION: Rate limiting validation
    
    Validates request rate limits to prevent brute force attacks.
    
    Args:
        user_id (str): User identifier (IP or user ID)
        action (str): Action being performed
        time_window (int): Time window in seconds
        max_attempts (int): Maximum attempts in time window
    
    Returns:
        Tuple[bool, str]: (is_valid, error_message)
    
    Note: This is a basic implementation. In production, use Redis or similar for distributed rate limiting.
    """
    # This would typically be implemented with a proper caching system
    # For now, this is a placeholder that always returns True
    # In production, implement with Redis or database-based rate limiting
    
    return True, "Rate limit check passed"
