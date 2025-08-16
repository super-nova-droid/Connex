"""
Honeypot Security Module
This module handles honeypot functionality for detecting unauthorized access attempts.
"""

import mysql.connector
import os
import html
import json
import re
from datetime import datetime
from flask import request
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Database configuration
DB_HOST = os.environ.get('DB_HOST')
DB_USER = os.environ.get('DB_USER')
DB_PASSWORD = os.environ.get('DB_PASSWORD')
DB_NAME = os.environ.get('DB_NAME')
DB_PORT = int(os.environ.get('DB_PORT', 3306))

def get_db_connection():
    """Get database connection"""
    return mysql.connector.connect(
        host=DB_HOST,
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        port=DB_PORT
    )

def sanitize_input(input_text):
    """
    Sanitize input to prevent injection attacks and encoding issues
    
    Args:
        input_text (str): Raw input text
    
    Returns:
        str: Sanitized and escaped text safe for storage
    """
    if not input_text or input_text == 'null':
        return 'null'
    
    # Convert to string and limit length
    text = str(input_text)[:500]  # Limit to 500 characters
    
    # HTML escape to prevent XSS
    text = html.escape(text, quote=True)
    
    # Remove or escape potentially dangerous characters
    # Remove control characters except newlines and tabs
    text = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', text)
    
    # Escape backslashes and quotes for SQL safety (even though we use parameterized queries)
    text = text.replace('\\', '\\\\').replace("'", "\\'").replace('"', '\\"')
    
    return text

def encode_for_json(data):
    """
    Safely encode data for JSON storage/transmission
    
    Args:
        data: Data to encode
    
    Returns:
        str: JSON-safe encoded string
    """
    try:
        # Use json.dumps to properly escape for JSON
        return json.dumps(data, ensure_ascii=True)
    except (TypeError, ValueError):
        # Fallback for non-serializable data
        return json.dumps(str(data), ensure_ascii=True)

def get_user_agent():
    """Get the User-Agent string from the client request"""
    # Get User-Agent from request headers
    user_agent = request.headers.get('User-Agent', 'Unknown')
    
    # Limit length to prevent database issues (most User-Agent strings are under 500 chars)
    if len(user_agent) > 500:
        user_agent = user_agent[:500] + "..."
    
    return user_agent

def analyze_user_agent(user_agent):
    """
    Analyze User-Agent string to detect bots vs browsers
    
    Args:
        user_agent (str): The User-Agent string
    
    Returns:
        dict: Analysis results with bot detection and browser info
    """
    user_agent_lower = user_agent.lower()
    
    # Common bot indicators
    bot_indicators = [
        'bot', 'crawler', 'spider', 'scraper', 'curl', 'wget', 'python', 
        'postman', 'httpie', 'requests', 'urllib', 'okhttp', 'java',
        'go-http-client', 'libwww-perl', 'php', 'ruby', 'node'
    ]
    
    # Common browser indicators
    browser_indicators = [
        'mozilla', 'chrome', 'firefox', 'safari', 'edge', 'opera', 
        'webkit', 'gecko', 'trident'
    ]
    
    is_likely_bot = any(indicator in user_agent_lower for indicator in bot_indicators)
    is_likely_browser = any(indicator in user_agent_lower for indicator in browser_indicators)
    
    # Determine client type
    if is_likely_bot and not is_likely_browser:
        client_type = "Bot/Crawler"
    elif is_likely_browser and not is_likely_bot:
        client_type = "Browser"
    elif not is_likely_browser and not is_likely_bot:
        client_type = "Unknown/Custom"
    else:
        client_type = "Mixed/Suspicious"
    
    return {
        'client_type': client_type,
        'is_likely_bot': is_likely_bot,
        'is_likely_browser': is_likely_browser,
        'user_agent': user_agent
    }

def log_honeypot_access(webpage="security questions", input1="null", input2="null", input3="null", description="accessed page"):
    """
    Log honeypot access attempt to the database with proper input sanitization
    
    Args:
        webpage (str): The webpage that was accessed (default: "security questions")
        input1 (str): First input field value (default: "null")
        input2 (str): Second input field value (default: "null") 
        input3 (str): Third input field value (default: "null")
        description (str): Description of the access attempt (default: "accessed page")
    
    Returns:
        bool: True if logged successfully, False otherwise
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get current timestamp
        access_time = datetime.now()
        
        # Get User-Agent string and sanitize it
        user_agent = get_user_agent()
        user_agent = sanitize_input(user_agent)
        
        # Sanitize all inputs to prevent injection attacks
        webpage_safe = sanitize_input(webpage)
        input1_safe = sanitize_input(input1)
        input2_safe = sanitize_input(input2)
        input3_safe = sanitize_input(input3)
        description_safe = sanitize_input(description)
        
        # Analyze User-Agent to detect bot vs browser
        ua_analysis = analyze_user_agent(user_agent)
        
        # Check if user_agent column exists in the table
        try:
            cursor.execute("DESCRIBE honeypot")
            columns = [col[0] for col in cursor.fetchall()]
            has_user_agent_column = 'user_agent' in columns
        except Exception as e:
            print(f"Error checking table structure: {e}")
            has_user_agent_column = False
        
        if has_user_agent_column:
            # Use new schema with user_agent column
            query = """
            INSERT INTO honeypot (webpage, input1, input2, input3, description, access_time, user_agent) 
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            """
            cursor.execute(query, (webpage_safe, input1_safe, input2_safe, input3_safe, description_safe, access_time, user_agent))
            print(f"Honeypot access logged: {webpage_safe} from {ua_analysis['client_type']} ({user_agent[:50]}...) at {access_time}")
            
            # Additional logging for form submissions with input data
            if description_safe == 'data input' and any(inp != 'null' for inp in [input1_safe, input2_safe, input3_safe]):
                print(f"SECURITY ALERT: Form data submitted to honeypot!")
                print(f"  Input1: {input1_safe[:100]}...")
                print(f"  Input2: {input2_safe[:100]}...")
                print(f"  Input3: {input3_safe[:100]}...")
                print(f"  User-Agent: {user_agent[:100]}...")
        else:
            # Fallback to old schema with ip_address column (store user_agent in description)
            enhanced_description = f"{description_safe} | User-Agent: {user_agent[:100]}..."
            enhanced_description = sanitize_input(enhanced_description)
            # Get fallback IP for compatibility
            fallback_ip = request.environ.get('REMOTE_ADDR', 'unknown')
            
            query = """
            INSERT INTO honeypot (webpage, input1, input2, input3, description, access_time, ip_address) 
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            """
            cursor.execute(query, (webpage_safe, input1_safe, input2_safe, input3_safe, enhanced_description, access_time, fallback_ip))
            print(f"Honeypot access logged (fallback): {webpage_safe} from {ua_analysis['client_type']} at {access_time}")
        
        conn.commit()
        return True
        
    except Exception as e:
        print(f"Error logging honeypot access: {e}")
        return False
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

def log_security_questions_access():
    """
    Specific function to log access to the security questions honeypot page
    """
    return log_honeypot_access(
        webpage="security questions",
        input1="null",
        input2="null", 
        input3="null",
        description="accessed page"
    )

def log_form_submission(form_data):
    """
    Log form submission attempts on honeypot pages
    
    Args:
        form_data (dict): Form data submitted by the user
    
    Returns:
        bool: True if logged successfully, False otherwise
    """
    try:
        # Extract form inputs, default to "null" if not present
        input1 = form_data.get('question1', 'null')
        input2 = form_data.get('question2', 'null')
        input3 = form_data.get('question3', 'null')
        
        # Sanitize inputs (limit length for security)
        input1 = str(input1)[:255] if input1 and input1 != 'null' else 'null'
        input2 = str(input2)[:255] if input2 and input2 != 'null' else 'null'
        input3 = str(input3)[:255] if input3 and input3 != 'null' else 'null'
        
        return log_honeypot_access(
            webpage="security questions",
            input1=input1,
            input2=input2,
            input3=input3,
            description="form submission attempt"
        )
        
    except Exception as e:
        print(f"Error logging form submission: {e}")
        return False

def get_honeypot_logs(limit=100):
    """
    Retrieve honeypot logs from the database
    
    Args:
        limit (int): Maximum number of logs to retrieve
    
    Returns:
        list: List of honeypot log entries
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # Check if user_agent column exists
        try:
            cursor.execute("DESCRIBE honeypot")
            columns = [col[0] for col in cursor.fetchall()]
            has_user_agent_column = 'user_agent' in columns
        except Exception as e:
            print(f"Error checking table structure: {e}")
            has_user_agent_column = False
        
        if has_user_agent_column:
            # Use new schema
            query = """
            SELECT *, user_agent as user_agent_info FROM honeypot 
            ORDER BY access_time DESC 
            LIMIT %s
            """
        else:
            # Use old schema but extract user_agent from description if available
            query = """
            SELECT *, ip_address, 
                   CASE 
                       WHEN description LIKE '%User-Agent:%' 
                       THEN SUBSTRING_INDEX(SUBSTRING_INDEX(description, 'User-Agent: ', -1), '...', 1)
                       ELSE 'Unknown'
                   END as user_agent_info
            FROM honeypot 
            ORDER BY access_time DESC 
            LIMIT %s
            """
        
        cursor.execute(query, (limit,))
        logs = cursor.fetchall()
        
        return logs
        
    except Exception as e:
        print(f"Error retrieving honeypot logs: {e}")
        return []
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

def get_suspicious_user_agents(days=7):
    """
    Get User-Agent strings that have accessed honeypot pages multiple times
    
    Args:
        days (int): Number of days to look back
    
    Returns:
        list: List of suspicious User-Agent strings with access counts and analysis
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # Check if user_agent column exists
        try:
            cursor.execute("DESCRIBE honeypot")
            columns = [col[0] for col in cursor.fetchall()]
            has_user_agent_column = 'user_agent' in columns
        except Exception as e:
            print(f"Error checking table structure: {e}")
            has_user_agent_column = False
        
        if has_user_agent_column:
            # Use new schema with user_agent column
            query = """
            SELECT user_agent, COUNT(*) as access_count, MAX(access_time) as last_access
            FROM honeypot 
            WHERE access_time >= DATE_SUB(NOW(), INTERVAL %s DAY)
            GROUP BY user_agent
            HAVING access_count > 1
            ORDER BY access_count DESC
            """
            cursor.execute(query, (days,))
            suspicious_agents = cursor.fetchall()
            
            # Add analysis for each User-Agent
            for agent in suspicious_agents:
                analysis = analyze_user_agent(agent['user_agent'])
                agent['client_type'] = analysis['client_type']
                agent['is_likely_bot'] = analysis['is_likely_bot']
                agent['is_likely_browser'] = analysis['is_likely_browser']
        else:
            # Use old schema - extract user_agent from description field
            query = """
            SELECT 
                CASE 
                    WHEN description LIKE '%User-Agent:%' 
                    THEN SUBSTRING_INDEX(SUBSTRING_INDEX(description, 'User-Agent: ', -1), '...', 1)
                    ELSE 'Unknown User-Agent'
                END as user_agent,
                COUNT(*) as access_count, 
                MAX(access_time) as last_access
            FROM honeypot 
            WHERE access_time >= DATE_SUB(NOW(), INTERVAL %s DAY)
            GROUP BY user_agent
            HAVING access_count > 1
            ORDER BY access_count DESC
            """
            cursor.execute(query, (days,))
            suspicious_agents = cursor.fetchall()
            
            # Add analysis for each User-Agent
            for agent in suspicious_agents:
                if agent['user_agent'] and agent['user_agent'] != 'Unknown User-Agent':
                    analysis = analyze_user_agent(agent['user_agent'])
                    agent['client_type'] = analysis['client_type']
                    agent['is_likely_bot'] = analysis['is_likely_bot']
                    agent['is_likely_browser'] = analysis['is_likely_browser']
                else:
                    agent['client_type'] = 'Unknown'
                    agent['is_likely_bot'] = False
                    agent['is_likely_browser'] = False
        
        return suspicious_agents
        
    except Exception as e:
        print(f"Error retrieving suspicious User-Agents: {e}")
        return []
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

def get_bot_statistics(days=7):
    """
    Get statistics about bot vs browser access attempts
    
    Args:
        days (int): Number of days to look back
    
    Returns:
        dict: Statistics about different client types
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # Check if user_agent column exists
        try:
            cursor.execute("DESCRIBE honeypot")
            columns = [col[0] for col in cursor.fetchall()]
            has_user_agent_column = 'user_agent' in columns
        except Exception as e:
            print(f"Error checking table structure: {e}")
            has_user_agent_column = False
        
        if has_user_agent_column:
            # Use new schema
            query = """
            SELECT user_agent, COUNT(*) as access_count
            FROM honeypot 
            WHERE access_time >= DATE_SUB(NOW(), INTERVAL %s DAY)
            GROUP BY user_agent
            """
        else:
            # Use old schema - extract from description
            query = """
            SELECT 
                CASE 
                    WHEN description LIKE '%User-Agent:%' 
                    THEN SUBSTRING_INDEX(SUBSTRING_INDEX(description, 'User-Agent: ', -1), '...', 1)
                    ELSE 'Unknown User-Agent'
                END as user_agent,
                COUNT(*) as access_count
            FROM honeypot 
            WHERE access_time >= DATE_SUB(NOW(), INTERVAL %s DAY)
            GROUP BY user_agent
            """
        
        cursor.execute(query, (days,))
        all_agents = cursor.fetchall()
        
        stats = {
            'total_accesses': 0,
            'bot_accesses': 0,
            'browser_accesses': 0,
            'unknown_accesses': 0,
            'suspicious_accesses': 0
        }
        
        for agent in all_agents:
            count = agent['access_count']
            stats['total_accesses'] += count
            
            if agent['user_agent'] and agent['user_agent'] != 'Unknown User-Agent':
                analysis = analyze_user_agent(agent['user_agent'])
                
                if analysis['client_type'] == 'Bot/Crawler':
                    stats['bot_accesses'] += count
                elif analysis['client_type'] == 'Browser':
                    stats['browser_accesses'] += count
                elif analysis['client_type'] == 'Mixed/Suspicious':
                    stats['suspicious_accesses'] += count
                else:
                    stats['unknown_accesses'] += count
            else:
                stats['unknown_accesses'] += count
        
        return stats
        
    except Exception as e:
        print(f"Error retrieving bot statistics: {e}")
        return {}
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()
