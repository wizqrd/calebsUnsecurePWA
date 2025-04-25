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

logging.basicConfig(filename='security_log.log', level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

def validatePassword(password):
    if len(password) < 8 or len(password) > 20:
        return False, "Password must be between 8 and 20 characters"
    
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter"
    
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter"
    
    if not re.search(r"[0-9]", password):
        return False, "Password must contain at least one number"
    
    if not re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]", password):
        return False, "Password must contain at least one special character"
    
    return True, "Password is valid"

def hashPassword(password):
    salt = bcrypt.gensalt()
    hashedPassword = bcrypt.hashpw(password.encode(), salt)
    return hashedPassword

def checkPassword(plainPassword, hashedPassword):
    return bcrypt.checkpw(plainPassword.encode(), hashedPassword)

def addEmailColumnIfNotExists():
    try:
        con = sql.connect("database_files/database.db")
        cur = con.cursor()
        cur.execute("PRAGMA table_info(users)")
        columns = [column[1] for column in cur.fetchall()]
        
        if "email" not in columns:
            cur.execute("ALTER TABLE users ADD COLUMN email TEXT")
            con.commit()
            logging.info("Added email column to users table")
        
        if "totp_secret" not in columns:
            cur.execute("ALTER TABLE users ADD COLUMN totp_secret TEXT")
            con.commit()
            logging.info("Added totp_secret column to users table")
            
        con.close()
    except Exception as e:
        logging.error(f"Error adding columns: {str(e)}")

def generateTOTPSecret():
    secret = pyotp.random_base32()
    return secret

def generateQRCode(username, secret):
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(username, issuer_name="Secure PWA")
    
    img = qrcode.make(uri)
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    img_str = base64.b64encode(buffered.getvalue()).decode()
    
    return f"data:image/png;base64,{img_str}"

def verifyTOTP(secret, token):
    totp = pyotp.TOTP(secret)
    return totp.verify(token)

def getTOTPSecret(username):
    try:
        con = sql.connect("database_files/database.db")
        cur = con.cursor()
        cur.execute("SELECT totp_secret FROM users WHERE username = ?", (username,))
        result = cur.fetchone()
        con.close()
        
        if result and result[0]:
            return result[0]
        return None
    except Exception as e:
        logging.error(f"Error getting TOTP secret: {str(e)}")
        return None

def insertUser(username, password, DoB, email=""):
    try:
        addEmailColumnIfNotExists()
        con = sql.connect("database_files/database.db")
        cur = con.cursor()
        hashedPassword = hashPassword(password)
        totp_secret = generateTOTPSecret()
        
        cur.execute(
            "INSERT INTO users (username,password,dateOfBirth,email,totp_secret) VALUES (?,?,?,?,?)",
            (username, hashedPassword, DoB, email, totp_secret),
        )
        con.commit()
        con.close()
        logging.info(f"New user created: {username}")
        return totp_secret
    except Exception as e:
        logging.error(f"Error creating user: {str(e)}")
        return None


def retrieveUsers(username, password):
    try:
        con = sql.connect("database_files/database.db")
        cur = con.cursor()
        cur.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cur.fetchone()
        
        if user is None:
            con.close()
            logging.warning(f"Failed login attempt: Username {username} not found")
            return False, None
        else:
            storedHash = user[2]
            
            updateVisitorCount()
            
            time.sleep(random.randint(80, 90) / 1000)
            
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
    try:
        with open("visitor_log.txt", "r") as file:
            number = int(file.read().strip())
            number += 1
        with open("visitor_log.txt", "w") as file:
            file.write(str(number))
    except Exception as e:
        logging.error(f"Error updating visitor count: {str(e)}")


def insertFeedback(feedback):
    try:
        con = sql.connect("database_files/database.db")
        cur = con.cursor()
        cur.execute("INSERT INTO feedback (feedback) VALUES (?)", (feedback,))
        con.commit()
        con.close()
        logging.info("New feedback inserted")
    except Exception as e:
        logging.error(f"Error inserting feedback: {str(e)}")


def listFeedback():
    try:
        con = sql.connect("database_files/database.db")
        cur = con.cursor()
        data = cur.execute("SELECT * FROM feedback").fetchall()
        con.close()
        
        with open("templates/partials/success_feedback.html", "w") as f:
            for row in data:
                f.write("<p>\n")
                f.write(f"{row[1]}\n")
                f.write("</p>\n")
        
        logging.info("Feedback list generated")
    except Exception as e:
        logging.error(f"Error listing feedback: {str(e)}")