"""
Security Questions Module
Handles all security question related functionality including:
- Setting up security questions for logged-in users
- Verifying security questions for password recovery
- Password reset functionality
- Forgot password flow initiation
"""

import mysql.connector
import re
from flask import request, redirect, url_for, flash, session, g, render_template
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps


def get_db_connection():
    """Get database connection - should be imported from main app"""
    from app import get_db_connection as app_get_db_connection
    return app_get_db_connection()


def login_required(f):
    """Login required decorator - should be imported from main app"""
    from app import login_required as app_login_required
    return app_login_required(f)


def security_questions_route():
    """
    Security questions route for password recovery, login completion, or additional authentication.
    Users can access this to set up or verify security questions.
    """
    if request.method == 'POST':
        # Get answers from the form
        question1_answer = request.form.get('question1', '').strip().lower()
        question2_answer = request.form.get('question2', '').strip().lower()
        question3_answer = request.form.get('question3', '').strip().lower()
        
        # Basic validation
        if not question1_answer or not question2_answer or not question3_answer:
            flash("Please answer all security questions.", "error")
            return render_template('security_questions.html')
        
        # Check if this is part of a signup process first (highest priority)
        if session.get('signup_method') == 'security_questions' and session.get('pending_signup'):
            return _handle_setup_security_questions(question1_answer, question2_answer, question3_answer)
        
        # Check if this is part of login process (second priority)
        elif session.get('login_step') == 'password_verified' and session.get('temp_user_id'):
            return _handle_login_security_questions(question1_answer, question2_answer, question3_answer)
        
        # Check if user is trying to set up security questions (logged in)
        elif g.user:
            return _handle_setup_security_questions(question1_answer, question2_answer, question3_answer)
        else:
            # User is not logged in and not in login/signup process - must be password recovery
            return _handle_verify_security_questions(question1_answer, question2_answer, question3_answer)
    
    # GET request - show the security questions form
    return render_template('security_questions.html')


def _handle_setup_security_questions(question1_answer, question2_answer, question3_answer):
    """Handle setting up security questions for logged-in users or signup completion"""
    
    # Check if this is part of a signup process without email
    if session.get('signup_method') == 'security_questions' and session.get('pending_signup'):
        return _complete_signup_with_security_questions(question1_answer, question2_answer, question3_answer)
    
    # Regular logged-in user setting up security questions
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Hash the security question answers
        hashed_q1 = generate_password_hash(question1_answer)
        hashed_q2 = generate_password_hash(question2_answer)
        hashed_q3 = generate_password_hash(question3_answer)
        
        # Update the user's security questions in the Users table
        cursor.execute("""
            UPDATE Users 
            SET sec_qn_1 = %s, sec_qn_2 = %s, sec_qn_3 = %s
            WHERE user_id = %s
        """, (hashed_q1, hashed_q2, hashed_q3, g.user))
        
        if cursor.rowcount > 0:
            flash("Security questions set up successfully!", "success")
            
            # Redirect based on user role after successful setup
            user_role = g.role
            if user_role == 'admin':
                return redirect(url_for('admin_dashboard'))
            elif user_role == 'volunteer':
                return redirect(url_for('volunteer_dashboard'))
            elif user_role == 'elderly':
                return redirect(url_for('home'))
            else:
                return redirect(url_for('home'))  # Default fallback
        else:
            flash("Failed to update security questions. Please try again.", "error")
            return render_template('security_questions.html')
        
        conn.commit()
        
    except mysql.connector.Error as err:
        from app import app
        app.logger.error(f"Database error setting security questions for user {g.user}: {err}")
        flash("An error occurred while saving your security questions. Please try again.", "error")
        if conn:
            conn.rollback()
    except Exception as e:
        from app import app
        app.logger.error(f"Unexpected error in security questions for user {g.user}: {e}")
        flash("An unexpected error occurred. Please try again.", "error")
        if conn:
            conn.rollback()
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()
    
    return render_template('security_questions.html')


def _handle_login_security_questions(question1_answer, question2_answer, question3_answer):
    """Handle security questions verification during login process"""
    temp_user_id = session.get('temp_user_id')
    temp_user_role = session.get('temp_user_role')
    temp_user_name = session.get('temp_user_name')
    
    if not temp_user_id or session.get('login_step') != 'password_verified':
        flash("Login session expired. Please log in again.", "error")
        return redirect(url_for('login'))
    
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # Get user's security questions
        cursor.execute("""
            SELECT sec_qn_1, sec_qn_2, sec_qn_3
            FROM Users
            WHERE user_id = %s
        """, (temp_user_id,))
        user_security = cursor.fetchone()
        
        if not user_security:
            flash("User account not found. Please log in again.", "error")
            return redirect(url_for('login'))
        
        # Check if security questions are set up
        sec_qn_1 = user_security.get('sec_qn_1', '')
        sec_qn_2 = user_security.get('sec_qn_2', '')
        sec_qn_3 = user_security.get('sec_qn_3', '')
        
        if (not sec_qn_1 or not sec_qn_2 or not sec_qn_3 or
            sec_qn_1 == 'null' or sec_qn_2 == 'null' or sec_qn_3 == 'null'):
            # User needs to set up security questions - treat this as setup
            hashed_q1 = generate_password_hash(question1_answer)
            hashed_q2 = generate_password_hash(question2_answer)
            hashed_q3 = generate_password_hash(question3_answer)
            
            # Update user's security questions
            cursor.execute("""
                UPDATE Users 
                SET sec_qn_1 = %s, sec_qn_2 = %s, sec_qn_3 = %s
                WHERE user_id = %s
            """, (hashed_q1, hashed_q2, hashed_q3, temp_user_id))
            
            if cursor.rowcount > 0:
                conn.commit()
                flash("Security questions set up successfully! Login complete.", "success")
                from app import app
                app.logger.info(f"Security questions set up during login for user {temp_user_name}")
            else:
                flash("Failed to set up security questions. Please try again.", "error")
                return render_template('security_questions.html')
        else:
            # Verify existing security questions
            if (check_password_hash(sec_qn_1, question1_answer) and 
                check_password_hash(sec_qn_2, question2_answer) and 
                check_password_hash(sec_qn_3, question3_answer)):
                flash("Security questions verified! Login complete.", "success")
                from app import app
                app.logger.info(f"Security questions verified during login for user {temp_user_name}")
            else:
                flash("One or more answers are incorrect. Please try again.", "error")
                from app import app
                app.logger.warning(f"Failed security question verification during login for user {temp_user_name}")
                return render_template('security_questions.html')
        
        # Complete login - move temp session data to permanent session
        session.clear()  # Clear all session data including temp data
        session['user_id'] = temp_user_id
        session['user_role'] = temp_user_role
        session['user_name'] = temp_user_name
        
        # Redirect based on role
        if temp_user_role == 'admin':
            return redirect(url_for('admin_dashboard'))
        elif temp_user_role == 'volunteer':
            return redirect(url_for('volunteer_dashboard'))
        elif temp_user_role == 'elderly':
            return redirect(url_for('home'))
        else:
            return redirect(url_for('home'))  # Default fallback
            
    except mysql.connector.Error as err:
        from app import app
        app.logger.error(f"Database error during login security questions for user {temp_user_id}: {err}")
        flash("An error occurred. Please try again.", "error")
        if conn:
            conn.rollback()
    except Exception as e:
        from app import app
        app.logger.error(f"Unexpected error during login security questions for user {temp_user_id}: {e}")
        flash("An unexpected error occurred. Please try again.", "error")
        if conn:
            conn.rollback()
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()
    
    return render_template('security_questions.html')


def _complete_signup_with_security_questions(question1_answer, question2_answer, question3_answer):
    """Complete user signup using security questions instead of email verification"""
    signup_data = session.get('pending_signup')
    if not signup_data:
        flash("Signup session expired. Please sign up again.", "error")
        return redirect(url_for('signup'))

    name = signup_data['username']
    password = signup_data['password']
    email = signup_data.get('email', '')  # Email might be empty
    dob = signup_data['dob']
    location_id = signup_data['location_id']
    is_volunteer = signup_data['is_volunteer']
    hashed_password = generate_password_hash(password)
    role = 'volunteer' if is_volunteer else 'elderly'
    
    # Hash the security question answers
    hashed_q1 = generate_password_hash(question1_answer)
    hashed_q2 = generate_password_hash(question2_answer)
    hashed_q3 = generate_password_hash(question3_answer)

    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Insert user into database with security questions
        if email:
            cursor.execute("""
                INSERT INTO Users (username, email, password, dob, location_id, role, sec_qn_1, sec_qn_2, sec_qn_3)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (name, email, hashed_password, dob, location_id, role, hashed_q1, hashed_q2, hashed_q3))
        else:
            cursor.execute("""
                INSERT INTO Users (username, email, password, dob, location_id, role, sec_qn_1, sec_qn_2, sec_qn_3)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (name, "null", hashed_password, dob, location_id, role, hashed_q1, hashed_q2, hashed_q3))
        
        conn.commit()
        
        # Clean up session after successful insertion
        session.pop('pending_signup', None)
        session.pop('signup_method', None)
        
        flash("Account created successfully with security questions!", "success")
        from app import app
        app.logger.info(f"User {name} signed up successfully without email verification using security questions.")
        return redirect(url_for('login'))
        
    except mysql.connector.Error as err:
        from app import app
        app.logger.error(f"Database error during signup completion: {err}")
        flash("Something went wrong. Please try again.", "error")
        if conn:
            conn.rollback()
        return redirect(url_for('signup'))
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()
    
    return render_template('security_questions.html')


def _handle_verify_security_questions(question1_answer, question2_answer, question3_answer):
    """Handle verifying security questions for password recovery"""
    # User is not logged in - they might be trying to recover password
    email = session.get('recovery_email')
    if not email:
        flash("Security questions session expired. Please start password recovery again.", "error")
        return redirect(url_for('login'))
    
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # Get user's security questions from Users table
        cursor.execute("""
            SELECT user_id, sec_qn_1, sec_qn_2, sec_qn_3
            FROM Users
            WHERE email = %s AND email != 'null'
        """, (email,))
        user_security = cursor.fetchone()
        
        if user_security:
            # Check if security questions are set up and not "null"
            if (not user_security['sec_qn_1'] or not user_security['sec_qn_2'] or not user_security['sec_qn_3'] or
                user_security['sec_qn_1'] == 'null' or user_security['sec_qn_2'] == 'null' or user_security['sec_qn_3'] == 'null'):
                flash("No security questions found for this account.", "error")
                return render_template('security_questions.html')
            
            # Verify answers using hashed comparison
            stored_q1_hash = user_security['sec_qn_1']
            stored_q2_hash = user_security['sec_qn_2']
            stored_q3_hash = user_security['sec_qn_3']
            
            if (check_password_hash(stored_q1_hash, question1_answer) and 
                check_password_hash(stored_q2_hash, question2_answer) and 
                check_password_hash(stored_q3_hash, question3_answer)):
                # Security questions verified - proceed to password reset
                session['security_verified'] = True
                session['verified_user_id'] = user_security['user_id']
                flash("Security questions verified! You can now reset your password.", "success")
                return redirect(url_for('reset_password'))
            else:
                flash("One or more answers are incorrect. Please try again.", "error")
                from app import app
                app.logger.warning(f"Failed security question attempt for email: {email}")
        else:
            flash("No account found with this email address.", "error")
            
    except mysql.connector.Error as err:
        from app import app
        app.logger.error(f"Database error verifying security questions for email {email}: {err}")
        flash("An error occurred while verifying your answers. Please try again.", "error")
    except Exception as e:
        from app import app
        app.logger.error(f"Unexpected error verifying security questions for email {email}: {e}")
        flash("An unexpected error occurred. Please try again.", "error")
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()
    
    return render_template('security_questions.html')
    
    return render_template('security_questions.html')


def reset_password_route():
    """
    Password reset route that requires security questions verification.
    """
    # Check if security questions have been verified
    if not session.get('security_verified') or not session.get('verified_user_id'):
        flash("Please verify your security questions first.", "error")
        return redirect(url_for('security_questions'))
    
    if request.method == 'POST':
        new_password = request.form.get('new_password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()
        
        # Basic validation
        if not new_password or not confirm_password:
            flash("Please fill in both password fields.", "error")
            return render_template('reset_password.html')
        
        if new_password != confirm_password:
            flash("Passwords do not match.", "error")
            return render_template('reset_password.html')
        
        if len(new_password) < 6:  # Basic password strength requirement
            flash("Password must be at least 6 characters long.", "error")
            return render_template('reset_password.html')
        
        conn = None
        cursor = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            # Hash the new password
            hashed_password = generate_password_hash(new_password)
            
            # Update the user's password
            cursor.execute("""
                UPDATE Users 
                SET password = %s, updated_at = NOW()
                WHERE user_id = %s
            """, (hashed_password, session['verified_user_id']))
            
            conn.commit()
            
            # Clear security verification session data
            session.pop('security_verified', None)
            session.pop('verified_user_id', None)
            session.pop('recovery_email', None)
            
            flash("Password reset successfully! You can now log in with your new password.", "success")
            from app import app
            app.logger.info(f"Password reset completed for user ID: {session.get('verified_user_id')}")
            return redirect(url_for('login'))
            
        except mysql.connector.Error as err:
            from app import app
            app.logger.error(f"Database error resetting password for user {session.get('verified_user_id')}: {err}")
            flash("An error occurred while resetting your password. Please try again.", "error")
            if conn:
                conn.rollback()
        except Exception as e:
            from app import app
            app.logger.error(f"Unexpected error resetting password for user {session.get('verified_user_id')}: {e}")
            flash("An unexpected error occurred. Please try again.", "error")
            if conn:
                conn.rollback()
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()
    
    # GET request - show password reset form
    return render_template('reset_password.html')


def forgot_password_route():
    """
    Forgot password route - initiates password recovery process.
    """
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        
        if not email:
            flash("Please enter your email address.", "error")
            return render_template('forgot_password.html')
        
        # Basic email validation
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            flash("Please enter a valid email address.", "error")
            return render_template('forgot_password.html')
        
        conn = None
        cursor = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor(dictionary=True)
            
            # Check if user exists and has security questions set up
            cursor.execute("""
                SELECT user_id, email, username, sec_qn_1, sec_qn_2, sec_qn_3
                FROM Users
                WHERE email = %s AND email != 'null'
            """, (email,))
            user = cursor.fetchone()
            
            if user and user['sec_qn_1'] and user['sec_qn_2'] and user['sec_qn_3'] and user['sec_qn_1'] != 'null':
                # Store email in session for security questions verification
                session['recovery_email'] = email
                flash("Please answer your security questions to reset your password.", "info")
                from app import app
                app.logger.info(f"Password recovery initiated for user: {email}")
                return redirect(url_for('security_questions'))
            else:
                # Don't reveal whether the email exists or not for security
                flash("If this email is registered and has security questions set up, you will be redirected to answer them.", "info")
                from app import app
                app.logger.warning(f"Password recovery attempt for non-existent or incomplete account: {email}")
                
        except mysql.connector.Error as err:
            from app import app
            app.logger.error(f"Database error in forgot password for email {email}: {err}")
            flash("An error occurred. Please try again later.", "error")
        except Exception as e:
            from app import app
            app.logger.error(f"Unexpected error in forgot password for email {email}: {e}")
            flash("An unexpected error occurred. Please try again later.", "error")
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()
    
    # GET request - show forgot password form
    return render_template('forgot_password.html')


def check_user_has_security_questions(user_id):
    """
    Check if a user has security questions set up.
    Returns True if they do, False otherwise.
    """
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT sec_qn_1, sec_qn_2, sec_qn_3 
            FROM Users 
            WHERE user_id = %s
        """, (user_id,))
        result = cursor.fetchone()
        
        if result:
            # Check if all three security questions are set and not "null"
            return (result[0] is not None and result[1] is not None and result[2] is not None and
                   result[0] != 'null' and result[1] != 'null' and result[2] != 'null')
        
        return False
        
    except mysql.connector.Error as err:
        from app import app
        app.logger.error(f"Database error checking security questions for user {user_id}: {err}")
        return False
    except Exception as e:
        from app import app
        app.logger.error(f"Unexpected error checking security questions for user {user_id}: {e}")
        return False
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


def delete_user_security_questions(user_id):
    """
    Delete security questions for a user (useful for admin functions).
    Returns True if successful, False otherwise.
    """
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            UPDATE Users 
            SET sec_qn_1 = 'null', sec_qn_2 = 'null', sec_qn_3 = 'null' 
            WHERE user_id = %s
        """, (user_id,))
        conn.commit()
        
        return cursor.rowcount > 0
        
    except mysql.connector.Error as err:
        from app import app
        app.logger.error(f"Database error deleting security questions for user {user_id}: {err}")
        if conn:
            conn.rollback()
        return False
    except Exception as e:
        from app import app
        app.logger.error(f"Unexpected error deleting security questions for user {user_id}: {e}")
        if conn:
            conn.rollback()
        return False
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()
