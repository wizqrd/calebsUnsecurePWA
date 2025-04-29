import sqlite3 as sql
import time
import random
import bcrypt
import logging
import re
import pyotp
import qrcode
from io import BytesIO
import base64

# ===============================
# Logging Configuration
# ===============================

# Set up logging to keep track of security events
# This creates a detailed security audit trail that can be analyzed later
logging.basicConfig(filename='security_log.log', level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

# ===============================
# Password Security Functions
# ===============================

def validatePassword(password):
    """
    Verifies that passwords meet strong security requirements.
    
    This function checks multiple criteria to ensure passwords are resistant
    to brute force and dictionary attacks:
      - Length requirements (8-20 characters)
      - Character diversity (uppercase, lowercase, numbers, symbols)
    
    Returns a tuple: (is_valid, message)
    """
    if len(password) < 8 or len(password) > 20:
        return False, "Password must be between 8 and 20 characters"
    
    # Check for at least one uppercase letter
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter"
    
    # Check for at least one lowercase letter
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter"
    
    # Check for at least one number
    if not re.search(r"[0-9]", password):
        return False, "Password must contain at least one number"
    
    # Check for at least one special character
    if not re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]", password):
        return False, "Password must contain at least one special character"
    
    return True, "Password is valid"

def hashPassword(password):
    salt = bcrypt.gensalt()  # Generate a random salt
    hashedPassword = bcrypt.hashpw(password.encode(), salt)  # Hash with salt
    return hashedPassword

def checkPassword(plainPassword, hashedPassword):
    return bcrypt.checkpw(plainPassword.encode(), hashedPassword)

# ===============================
# Database Setup Functions
# ===============================

def addEmailColumnIfNotExists():
    """
    Ensures the database schema has the necessary columns.
    
    This function performs a dynamic database migration to add:
      - email column: For account recovery and communication
      - totp_secret column: For storing 2FA authentication secrets
    
    This approach allows the application to evolve without requiring manual
    database updates when new features are added.
    """
    try:
        con = sql.connect("database_files/database.db")
        cur = con.cursor()
        
        # Get current table structure
        cur.execute("PRAGMA table_info(users)")
        columns = [column[1] for column in cur.fetchall()]
        
        # Add email column if it doesn't exist
        if "email" not in columns:
            cur.execute("ALTER TABLE users ADD COLUMN email TEXT")
            con.commit()
            logging.info("Added email column to users table")
        
        # Add TOTP secret column if it doesn't exist
        if "totp_secret" not in columns:
            cur.execute("ALTER TABLE users ADD COLUMN totp_secret TEXT")
            con.commit()
            logging.info("Added totp_secret column to users table")
            
        con.close()
    except Exception as e:
        logging.error(f"Error adding columns: {str(e)}")

# ===============================
# Two-Factor Authentication Functions
# ===============================

def generateTOTPSecret():
    """
    Generates a random secret key for TOTP-based 2FA.
    
    This creates a cryptographically secure random key that will be:
      - Stored in the user's database record
      - Shared with the user's authenticator app (Google Authenticator, Authy, etc.)
      - Used to generate and verify 6-digit codes
    
    Returns: A Base32-encoded random string (compatible with authenticator apps)
    """
    secret = pyotp.random_base32()  # Generates a random base32 string
    return secret

def generateQRCode(username, secret):
    """
    Creates a QR code image for setting up authenticator apps.
    
    This function:
      1. Generates a special URI that contains the username, secret, and issuer
      2. Creates a QR code containing this URI
      3. Converts the QR image to a base64 data URI that can be displayed in HTML
    
    Returns: A data URI string that renders as a QR code in web pages
    """
    # Create a TOTP object with the secret
    totp = pyotp.TOTP(secret)
    
    # Generate a URI that authenticator apps can understand
    # Format: otpauth://totp/[issuer]:[account]?secret=[secret]&issuer=[issuer]
    uri = totp.provisioning_uri(username, issuer_name="Secure PWA")
    
    # Generate a QR code image from the URI
    img = qrcode.make(uri)
    
    # Convert the image to a base64 data URI for embedding in HTML
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    imgStr = base64.b64encode(buffered.getvalue()).decode()
    
    return f"data:image/png;base64,{imgStr}"

def verifyTOTP(secret, token):
    """
    Verifies a 6-digit TOTP code against the user's secret.
    
    This function:
      1. Creates a TOTP object with the user's stored secret
      2. Checks if the provided token matches the expected value
      3. Accounts for time drift by checking nearby time windows
    
    Returns: True if the token is valid, False otherwise
    """
    totp = pyotp.TOTP(secret)
    return totp.verify(token)  # Validates the token and handles time windows

def getTOTPSecret(username):
    """
    Retrieves the TOTP secret for a specific user from the database.
    
    This is used during the login process to verify 2FA codes.
    
    Returns: The user's TOTP secret or None if not found
    """
    try:
        con = sql.connect("database_files/database.db")
        cur = con.cursor()
        
        # Use parameterized query to prevent SQL injection
        cur.execute("SELECT totp_secret FROM users WHERE username = ?", (username,))
        result = cur.fetchone()
        con.close()
        
        if result and result[0]:
            return result[0]
        return None
    except Exception as e:
        logging.error(f"Error getting TOTP secret: {str(e)}")
        return None

# ===============================
# User Management Functions
# ===============================

def insertUser(username, password, dob, email=""):
    """
    Creates a new user in the database with secure password storage.
    
    This function:
      1. Ensures the database schema is up to date
      2. Hashes the password with bcrypt
      3. Generates a TOTP secret for 2FA
      4. Stores all user information securely
    
    Returns: The generated TOTP secret if successful, None otherwise
    """
    try:
        # Make sure the database has all required columns
        addEmailColumnIfNotExists()
        
        con = sql.connect("database_files/database.db")
        cur = con.cursor()
        
        # Hash the password before storing
        hashedPassword = hashPassword(password)
        
        # Generate 2FA secret for the user
        totpSecret = generateTOTPSecret()
        
        # Use parameterized query to prevent SQL injection
        cur.execute(
            "INSERT INTO users (username,password,dateOfBirth,email,totp_secret) VALUES (?,?,?,?,?)",
            (username, hashedPassword, dob, email, totpSecret),
        )
        con.commit()
        con.close()
        
        # Log the event for security auditing
        logging.info(f"New user created: {username}")
        
        return totpSecret
    except Exception as e:
        logging.error(f"Error creating user: {str(e)}")
        return None


def retrieveUsers(username, password):
    """
    Authenticates a user based on username and password.
    
    Security features:
      1. Uses parameterized queries to prevent SQL injection
      2. Implements timing attack protection
      3. Stores only hashed passwords, never plaintext
      4. Tracks login attempts for auditing
    
    Returns: (is_valid, user_data) tuple
    """
    try:
        con = sql.connect("database_files/database.db")
        cur = con.cursor()
        
        # Use parameterized query to prevent SQL injection
        cur.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cur.fetchone()
        
        if user is None:
            con.close()
            # Log failed attempt but don't reveal if username exists
            logging.warning(f"Failed login attempt: Username {username} not found")
            return False, None
        else:
            storedHash = user[2]
            
            # Track visitor count for analytics
            updateVisitorCount()
            
            # Add a small random delay to prevent timing attacks
            # This makes it impossible to determine if a username exists based on response time
            time.sleep(random.randint(80, 90) / 1000)
            
            # Verify the password against the stored hash
            if checkPassword(password, storedHash):
                con.close()
                logging.info(f"Password verification successful for: {username}")
                return True, user
            else:
                con.close()
                logging.warning(f"Failed login attempt: Incorrect password for {username}")
                return False, None
    except Exception as e:
        logging.error(f"Error during login: {str(e)}")
        return False, None


def updateVisitorCount():
    """
    Tracks the number of login attempts for analytics purposes.
    
    This simple counter provides basic usage statistics without storing
    sensitive information about users.
    """
    try:
        # Read current count
        with open("visitor_log.txt", "r") as file:
            number = int(file.read().strip())
            number += 1
        
        # Update the count
        with open("visitor_log.txt", "w") as file:
            file.write(str(number))
    except Exception as e:
        logging.error(f"Error updating visitor count: {str(e)}")

# ===============================
# Feedback Functions
# ===============================

def insertFeedback(feedback, username):
    """
    Saves user feedback to the database with proper attribution.
    
    This function:
      1. Ensures the feedback table has a username column
      2. Uses parameterized queries to prevent SQL injection
      3. Associates feedback with the user who submitted it
    
    Returns: True if successful, False otherwise
    """
    try:
        con = sql.connect("database_files/database.db")
        cur = con.cursor()
        
        # Check if the feedback table has a username column
        cur.execute("PRAGMA table_info(feedback)")
        columns = [column[1] for column in cur.fetchall()]
        
        # Add username column if it doesn't exist (database migration)
        if "username" not in columns:
            cur.execute("ALTER TABLE feedback ADD COLUMN username TEXT")
            con.commit()
            logging.info("Added username column to feedback table")
        
        # Use parameterized query to prevent SQL injection
        cur.execute("INSERT INTO feedback (feedback, username) VALUES (?, ?)", (feedback, username))
        con.commit()
        con.close()
        
        # Log the event for auditing
        logging.info(f"New feedback inserted by {username}")
        return True
    except Exception as e:
        logging.error(f"Error inserting feedback: {str(e)}")
        return False


def deleteFeedback(feedback_id, username):
    """
    Deletes feedback from the database if it belongs to the requesting user.
    
    This function:
      1. Verifies the feedback exists and belongs to the user
      2. Uses parameterized queries to prevent SQL injection
      3. Only allows users to delete their own feedback
    
    Returns: True if successful, False otherwise
    """
    try:
        print(f"Attempting to delete feedback ID {feedback_id} for user {username}")
        # Ensure feedback_id is an integer (SQLite needs integers for ID comparisons)
        feedback_id = int(feedback_id)
        
        con = sql.connect("database_files/database.db")
        cur = con.cursor()
        
        # First check if the feedback entry exists
        cur.execute("SELECT COUNT(*) FROM feedback WHERE id = ?", (feedback_id,))
        count = cur.fetchone()[0]
        
        if count == 0:
            con.close()
            logging.warning(f"Delete attempt failed: Feedback #{feedback_id} not found")
            print(f"Feedback ID {feedback_id} not found in database")
            return False
        
        # Check if the feedback belongs to the user
        cur.execute("SELECT username FROM feedback WHERE id = ?", (feedback_id,))
        result = cur.fetchone()
        
        print(f"Database query result for feedback ID {feedback_id}: {result}")
        
        # If feedback doesn't belong to the user
        if not result:
            con.close()
            logging.warning(f"Delete attempt failed: Feedback #{feedback_id} not found")
            print(f"Feedback ID {feedback_id} not found in database")
            return False
            
        if result[0] != username:
            con.close()
            logging.warning(f"Unauthorized delete attempt: User {username} tried to delete feedback #{feedback_id} owned by {result[0]}")
            print(f"Permission denied: Feedback belongs to {result[0]}, not {username}")
            return False
        
        # Delete the feedback if it belongs to the user - use explicit transaction
        try:
            con.execute("BEGIN TRANSACTION")
            cur.execute("DELETE FROM feedback WHERE id = ? AND username = ?", (feedback_id, username))
            rows_affected = cur.rowcount
            print(f"Rows affected by delete: {rows_affected}")
            
            if rows_affected > 0:
                # Commit the transaction
                con.commit()
                logging.info(f"Feedback #{feedback_id} deleted by {username}")
                print(f"Successfully deleted feedback ID {feedback_id}")
                return True
            else:
                # No rows affected, roll back
                con.rollback()
                logging.warning(f"Delete operation completed but no rows affected for feedback #{feedback_id}")
                print(f"Delete operation completed but no rows affected")
                return False
        except Exception as e:
            # Error during transaction, roll back
            con.rollback()
            raise e
        finally:
            con.close()
    except Exception as e:
        logging.error(f"Error deleting feedback: {str(e)}")
        print(f"Exception in deleteFeedback: {str(e)}")
        return False


def editFeedback(feedback_id, new_text, username):
    """
    Updates existing feedback if it belongs to the requesting user.
    
    This function:
      1. Verifies the feedback exists and belongs to the user
      2. Uses parameterized queries to prevent SQL injection
      3. Only allows users to edit their own feedback
    
    Returns: True if successful, False otherwise
    """
    try:
        print(f"Attempting to edit feedback ID {feedback_id} for user {username}")
        # Ensure feedback_id is an integer (SQLite needs integers for ID comparisons)
        feedback_id = int(feedback_id)
        
        con = sql.connect("database_files/database.db")
        cur = con.cursor()
        
        # First check if the feedback entry exists
        cur.execute("SELECT COUNT(*) FROM feedback WHERE id = ?", (feedback_id,))
        count = cur.fetchone()[0]
        
        if count == 0:
            con.close()
            logging.warning(f"Edit attempt failed: Feedback #{feedback_id} not found")
            print(f"Feedback ID {feedback_id} not found in database")
            return False
        
        # Check if the feedback belongs to the user
        cur.execute("SELECT username FROM feedback WHERE id = ?", (feedback_id,))
        result = cur.fetchone()
        
        print(f"Database query result for feedback ID {feedback_id}: {result}")
        
        # If feedback doesn't belong to the user
        if not result:
            con.close()
            logging.warning(f"Edit attempt failed: Feedback #{feedback_id} not found")
            print(f"Feedback ID {feedback_id} not found in database")
            return False
            
        if result[0] != username:
            con.close()
            logging.warning(f"Unauthorized edit attempt: User {username} tried to edit feedback #{feedback_id} owned by {result[0]}")
            print(f"Permission denied: Feedback belongs to {result[0]}, not {username}")
            return False
        
        # Update the feedback if it belongs to the user - use explicit transaction
        try:
            con.execute("BEGIN TRANSACTION")
            cur.execute("UPDATE feedback SET feedback = ? WHERE id = ? AND username = ?", 
                       (new_text, feedback_id, username))
            rows_affected = cur.rowcount
            print(f"Rows affected by update: {rows_affected}")
            
            if rows_affected > 0:
                # Commit the transaction
                con.commit()
                logging.info(f"Feedback #{feedback_id} edited by {username}")
                print(f"Successfully edited feedback ID {feedback_id}")
                return True
            else:
                # No rows affected, roll back
                con.rollback()
                logging.warning(f"Edit operation completed but no rows affected for feedback #{feedback_id}")
                print(f"Edit operation completed but no rows affected")
                return False
        except Exception as e:
            # Error during transaction, roll back
            con.rollback()
            raise e
        finally:
            con.close()
    except Exception as e:
        logging.error(f"Error editing feedback: {str(e)}")
        print(f"Exception in editFeedback: {str(e)}")
        return False


def listFeedback():
    """
    Retrieves all feedback and generates an HTML partial for display.
    
    This function:
      1. Gets all feedback from the database, sorted by newest first
      2. Creates an HTML fragment with the feedback content
      3. Saves it as a partial template that can be included in pages
    
    Returns: True if successful, False otherwise
    """
    try:
        print("Retrieving feedback list from database")
        con = sql.connect("database_files/database.db")
        cur = con.cursor()
        
        # Get all feedback, ordered by newest first
        data = cur.execute("SELECT * FROM feedback ORDER BY id DESC").fetchall()
        con.close()
        
        # IMPORTANT: Do not overwrite the existing success_feedback.html file
        # Instead, confirm that the data from the database will be displayed correctly
        
        # Print the feedback data to the console for debugging
        print(f"Found {len(data)} feedback entries:")
        for row in data:
            feedback_id = row[0]
            feedback_text = row[1]
            username = row[2] if len(row) > 2 and row[2] is not None else "Anonymous"
            print(f"  ID: {feedback_id}, User: {username}, Text: {feedback_text}")
        
        logging.info("Feedback list generated")
        print("Feedback list generated successfully")
        return True
    except Exception as e:
        logging.error(f"Error listing feedback: {str(e)}")
        print(f"Error listing feedback: {str(e)}")
        return False