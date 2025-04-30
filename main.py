from flask import Flask, render_template, request, redirect, session, jsonify
from flask_limiter import Limiter  # For rate limiting to prevent abuse
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect  # For Cross-Site Request Forgery protection
import html
import re
import secrets  # For generating cryptographically secure random values
import user_management as dbHandler  # Custom module for database operations
import sqlite3 as sql  # For database operations
import logging
import datetime

# ===============================
# App setup and configuration
# ===============================

# Initialise the Flask application
app = Flask(__name__)

# Generate a secure random key for signing session cookies
# This prevents session hijacking attacks where attackers try to steal user sessions
app.secret_key = secrets.token_hex(32)  # Creates a 64-character hexadecimal string (32 bytes of randomness)

# Enable CSRF protection for all forms in the application
# This prevents attackers from tricking users into submitting malicious requests
csrf = CSRFProtect(app)

# Set up rate limiting to prevent brute force attacks and abuse
# This monitors IP addresses and blocks excessive requests
limiter = Limiter(
    get_remote_address,  # Function that returns the client's IP address
    app=app,
    default_limits=["200 per day", "50 per hour"],  # Default limits for all routes
    storage_uri="memory://",  # Store rate limiting data in memory
)

# Set up logging
logging.basicConfig(
    filename='app_errors.log',
    level=logging.ERROR,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Create a function to log errors
def logError(error_code, message, details=None):
    error_data = {
        'code': error_code,
        'message': message,
        'details': details,
        'timestamp': datetime.datetime.now().isoformat()
    }
    logging.error(f"ERROR {error_code}: {message} - {details}")
    print(f"ERROR {error_code}: {message}")

# ===============================
# Helper functions for security
# ===============================

# Sanitise user input to prevent XSS (Cross-Site Scripting) attacks
# XSS attacks occur when malicious scripts are injected into trusted websites
def sanitiseInput(input_text):
    # Convert special characters to HTML entities (e.g., < becomes &lt;)
    # This prevents browsers from interpreting them as HTML/JavaScript
    return html.escape(input_text)

# Extra safety for HTML attributes to prevent attribute-based XSS attacks
# These attacks involve breaking out of HTML attributes to inject code
def sanitiseAttributeValue(value):
    if value is None:
        return ""
    # Remove characters that could break out of HTML attributes
    sanitised = re.sub(r'[&<>"\'`=]', '', str(value))
    # Block dangerous URL protocols like javascript: that can execute code
    sanitised = re.sub(r'^(javascript|data|vbscript):', '', sanitised, flags=re.IGNORECASE)
    return sanitised

# Validate redirect URLs to prevent open redirect vulnerabilities
# Open redirects can be used for phishing by sending users to malicious sites
def isValidRedirect(url):
    allowedDomains = ["localhost", "127.0.0.1"]
    # Allow internal paths starting with /
    if url.startswith('/'):
        return True
    # Check external URLs against whitelist of allowed domains
    pattern = r'^https?://([^/]+).*$'
    match = re.match(pattern, url)
    if match:
        domain = match.group(1)
        for allowed in allowedDomains:
            if domain == allowed or domain.endswith("." + allowed):
                return True
    return False

# Handle URL redirection with security validation
def handleRedirectParams():
    if request.method == "GET" and request.args.get("url"):
        url = request.args.get("url", "")
        # Sanitise URL parameter
        url = sanitiseAttributeValue(url)
        if isValidRedirect(url):
            return redirect(url, code=302)
        else:
            return redirect("/", code=302)
    return None

# Validate username format and length
def validateUsername(username, template_path):
    if len(username) < 3 or len(username) > 20:
        return render_template(template_path, error="Username must be between 3 and 20 characters")
    
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        return render_template(template_path, error="Username can only contain letters, numbers, and underscores")
    
    return None

# Handle TOTP verification logic
def handleTOTPVerification(username, token, success_message, template_path, is_setup=False):
    # Get the TOTP secret for this user
    secret = dbHandler.getTOTPSecret(username)
    if not secret:
        logError(3001, "TOTP secret not found", {'username': username})
        return render_template("/verify_2fa.html", error="Invalid credentials", username=username)
    
    # Generate QR code for scanning with authenticator app
    qrCode = dbHandler.generateQRCode(username, secret)
    
    # Verify the token against the secret
    if dbHandler.verifyTOTP(secret, token):
        # 2FA verified - complete login
        if not is_setup:
            session.pop('temp_username', None)
        session['user'] = username
        session['message'] = success_message
        return redirect("/success.html")
    else:
        # Invalid token, show error
        return render_template(template_path, 
                          error="Invalid code. Please try again.", 
                          qr_code=qrCode if is_setup else None,
                          secret=secret if is_setup else None,
                          username=username)

# ===============================
# Security middleware
# ===============================

# Check for sensitive information in URL parameters (before each request)
# This prevents accidental exposure of sensitive data in browser history, logs, etc.
@app.before_request
def checkSensitiveParameters():
    # Only check GET requests (where parameters appear in the URL)
    if request.method == 'GET':
        # List of parameter names that should never be in a URL
        sensitive_params = ['username', 'userName', 'user', 'password', 'apikey', 'key', 'token', 'secret']
        
        # Check if any sensitive parameters are in the query string
        for param in sensitive_params:
            if param.lower() in [k.lower() for k in request.args.keys()]:
                # Handle API requests differently than web pages
                if '/UI/' in request.path or '/api/' in request.path:
                    return jsonify({
                        "error": "Sensitive information should not be passed in URL parameters",
                        "code": 400
                    }), 400
                # For regular web pages, redirect to a safe page
                return redirect("/")

# Add security headers to all responses to protect against various attacks
@app.after_request
def setSecurityHeaders(response):
    # Clickjacking protection - prevents the page from being embedded in iframes
    response.headers['X-Frame-Options'] = 'DENY'
    
    # Prevents browsers from MIME-sniffing (guessing file types)
    # This stops attacks that rely on a browser misinterpreting file types
    response.headers['X-Content-Type-Options'] = 'nosniff'
    
    # Forces HTTPS usage for a specified time period
    # Protects against protocol downgrade attacks and cookie theft
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    # Enables browser's built-in XSS protection
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    # Hide server information to prevent fingerprinting
    response.headers['Server'] = 'WebServer'
    
    # Content Security Policy (CSP)
    # Restricts which resources (scripts, styles, images) can be loaded
    # This is one of the strongest defenses against XSS attacks
    csp = (
        "default-src 'self'; "            # Default: only allow from same origin
        "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "  # Allow inline scripts and eval for functionality
        "style-src 'self' 'unsafe-inline'; "  # Allow inline styles
        "img-src 'self' data:; "          # Images: from same origin or data: URLs (for QR codes)
        "font-src 'self'; "               # Fonts: only from same origin
        "connect-src 'self'; "            # AJAX/WebSocket: only to same origin  
        "frame-src 'none'; "              # Frames: not allowed
        "form-action 'self'"              # Forms: can only submit to same origin
    )
    response.headers['Content-Security-Policy'] = csp
    
    return response

# ===============================
# Login/Registration Routes
# ===============================

# Home page and login route
@app.route("/index.html", methods=["POST", "GET"])
@app.route("/", methods=["POST", "GET"])
@limiter.limit("10 per minute")  # Prevent brute force login attempts
def home():
    error = None
    # Get message from session instead of URL (more secure)
    message = None
    if 'message' in session:
        message = session.pop('message')
    
    # If user is already logged in, redirect to success page
    if 'user' in session:
        return redirect("/success.html")
        
    # Handle redirect parameter (with security validation)
    redirect_response = handleRedirectParams()
    if redirect_response:
        return redirect_response
            
    # Handle login form submission
    if request.method == "POST":
        # Only process login if user is not already logged in
        username = sanitiseInput(request.form["username"])
        password = request.form["password"]
        
        # Validate username
        validation_result = validateUsername(username, "/index.html")
        if validation_result:
            return validation_result
        
        # Check password against database (password verification happens in dbHandler)
        isPasswordValid, user = dbHandler.retrieveUsers(username, password)
        
        if isPasswordValid:
            # Store username temporarily for 2FA process
            session['temp_username'] = username
            # Redirect to 2FA verification page
            return render_template("/verify_2fa.html", username=username)
        else:
            # Generic error message doesn't reveal if username exists
            # This prevents username enumeration attacks
            error = "Invalid username or password"
            return render_template("/index.html", error=error)
    else:
        # Not logged in, show login form
        return render_template("/index.html", message=message, error=error)

# Registration route
@app.route("/signup.html", methods=["POST", "GET"])
@limiter.limit("5 per minute")  # Prevent spam registrations
def signup():
    error = None
    
    # If user is already logged in, redirect to success page
    if 'user' in session:
        return redirect("/success.html")
        
    # Handle redirect parameter (with security validation)
    redirect_response = handleRedirectParams()
    if redirect_response:
        return redirect_response
            
    # Handle registration form submission
    if request.method == "POST":
        # Sanitise all user inputs to prevent XSS
        username = sanitiseInput(request.form["username"])
        email = sanitiseInput(request.form["email"])
        password = request.form["password"]  # Not sanitised as it will be hashed
        dob = sanitiseInput(request.form["dob"])
        
        # Validate username
        validation_result = validateUsername(username, "/signup.html")
        if validation_result:
            return validation_result
        
        # Validate password complexity
        isValid, message = dbHandler.validatePassword(password)
        if not isValid:
            error = message
            return render_template("/signup.html", error=error)
            
        # Create user and get TOTP secret for 2FA setup
        totpSecret = dbHandler.insertUser(username, password, dob, email)
        if totpSecret:
            # Generate QR code for scanning with authenticator app
            qrCode = dbHandler.generateQRCode(username, totpSecret)
            return render_template("/setup_2fa.html", qr_code=qrCode, secret=totpSecret, username=username)
        else:
            error = "An error occurred during account creation"
            return render_template("/signup.html", error=error)
    else:
        # Display registration form
        return render_template("/signup.html", error=error)

# Logout route
@app.route("/logout")
def logout():
    # Remove user data from session
    session.pop('user', None)
    session.pop('temp_username', None)
    # Store message in session instead of URL parameter (more secure)
    session['message'] = "You have been logged out successfully."
    return redirect("/")

# ===============================
# Two-Factor Authentication (2FA) Routes
# ===============================

# Route to display QR code for authenticator app setup
@app.route("/show_qr")
def showQRCode():
    if request.args.get("username"):
        username = sanitiseInput(request.args.get("username"))
        
        # Security check: Make sure this is a legitimate verification session
        if 'temp_username' not in session or session['temp_username'] != username:
            return redirect("/")
            
        # Get the TOTP secret for this user
        secret = dbHandler.getTOTPSecret(username)
        if secret:
            # Generate QR code for scanning with authenticator app
            qrCode = dbHandler.generateQRCode(username, secret)
            return render_template("/verify_2fa.html", 
                               username=username,
                               show_qr=True,
                               qr_code=qrCode,
                               secret=secret)
    
    return redirect("/")

# Route to verify 2FA code during initial setup
@app.route("/verify_2fa", methods=["POST"])
@limiter.limit("5 per minute")  # Prevent brute force 2FA attacks
def verify2FASetup():
    if request.method == "POST":
        username = request.form["username"]
        token = request.form["token"]  # The 6-digit code from authenticator app
        
        success_message = f"Welcome {username}! Your 2FA setup was successful."
        return handleTOTPVerification(username, token, success_message, "/setup_2fa.html", is_setup=True)

# Route to verify 2FA code during login
@app.route("/verify_login_2fa", methods=["POST"])
@limiter.limit("5 per minute")  # Prevent brute force 2FA attacks
def verifyLogin2FA():
    if request.method == "POST":
        username = request.form["username"]
        token = request.form["token"]  # The 6-digit code from authenticator app
        
        # Security check: Make sure this is a legitimate verification session
        if 'temp_username' not in session or session['temp_username'] != username:
            return redirect("/")
        
        success_message = f"Welcome {username}! You have successfully logged in."
        return handleTOTPVerification(username, token, success_message, "/verify_2fa.html")

# ===============================
# Feedback and Content Routes
# ===============================

# Route for viewing and submitting feedback
@app.route("/success.html", methods=["POST", "GET"])
@limiter.limit("10 per minute")
def addFeedback():
    # Require login to access this page
    if 'user' not in session:
        return redirect("/")
    
    # For GET requests, display the feedback page with feedback from database
    if request.method == "GET":
        # Fetch feedback items directly from the database
        try:
            # Connect to the database
            con = sql.connect("database_files/database.db")
            cur = con.cursor()
            
            # Get all feedback, ordered by newest first
            feedback_items = []
            data = cur.execute("SELECT * FROM feedback ORDER BY id DESC").fetchall()
            
            # Process each row into a dictionary for the template
            for row in data:
                feedback_id = row[0]
                feedback_text = row[1]
                username = row[2] if len(row) > 2 and row[2] is not None else "Anonymous"
                
                feedback_items.append({
                    'id': feedback_id,
                    'text': feedback_text,
                    'username': username
                })
            
            con.close()
            
            # Return the template with the feedback items from database
            return render_template("/success.html", 
                                  state=True, 
                                  value=session['user'], 
                                  feedback_items=feedback_items)
                                  
        except Exception as e:
            print(f"Error fetching feedback: {str(e)}")
            session['message'] = "Error loading feedback items."
            return render_template("/success.html", state=True, value=session['user'], feedback_items=[])
    
    # For POST requests, process new feedback submission
    if request.method == "POST":
        # Validate CSRF token to prevent cross-site request forgery
        if 'csrf_token' not in request.form:
            session['message'] = "Invalid request. Please try again."
            return redirect("/success.html")
        
        # Get and validate feedback text
        feedback = request.form.get("feedback", "")
        if not feedback or len(feedback.strip()) == 0:
            session['message'] = "Feedback cannot be empty."
            return redirect("/success.html")
            
        # Sanitise input to prevent XSS attacks
        feedback = sanitiseInput(feedback)
        
        # Limit feedback length to prevent abuse
        if len(feedback) > 500:
            feedback = feedback[:500]
        
        # Store feedback in database
        try:
            # Connect to the database directly
            con = sql.connect("database_files/database.db")
            cur = con.cursor()
            
            # Insert the new feedback with parameterised query to prevent SQL injection
            cur.execute("INSERT INTO feedback (feedback, username) VALUES (?, ?)", 
                       (feedback, session['user']))
            con.commit()
            con.close()
            
            session['message'] = "Feedback submitted successfully!"
        except Exception as e:
            print(f"Error inserting feedback: {str(e)}")
            session['message'] = "Failed to submit feedback. Please try again."
        
        # Refresh page to show new feedback
        return redirect("/success.html")

# Route for editing feedback
@app.route("/edit_feedback", methods=["POST"])
@limiter.limit("10 per minute")
def editFeedback():
    # Require login to access this functionality
    if 'user' not in session:
        return jsonify({"success": False, "message": "You must be logged in"}), 401
    
    # Validate CSRF token to prevent cross-site request forgery
    if 'csrf_token' not in request.form:
        return jsonify({"success": False, "message": "Invalid request"}), 400
    
    try:
        # Get feedback ID and new text from request
        feedback_id = request.form.get("feedback_id")
        new_text = request.form.get("feedback_text")
        
        # Validate inputs
        if not feedback_id or not new_text or len(new_text.strip()) == 0:
            return jsonify({"success": False, "message": "Invalid input"}), 400
            
        # Sanitise input to prevent XSS attacks
        new_text = sanitiseInput(new_text)
        
        # Limit feedback length to prevent abuse
        if len(new_text) > 500:
            new_text = new_text[:500]
        
        # Connect to database
        con = sql.connect("database_files/database.db")
        cur = con.cursor()
        
        # First check if the feedback belongs to the current user
        result = cur.execute("SELECT username FROM feedback WHERE id = ?", (feedback_id,)).fetchone()
        
        if not result:
            con.close()
            return jsonify({"success": False, "message": "Feedback not found"}), 404
            
        # Verify ownership - users can only edit their own feedback
        if result[0] != session['user']:
            con.close()
            return jsonify({"success": False, "message": "You can only edit your own feedback"}), 403
        
        # Update the feedback
        cur.execute("UPDATE feedback SET feedback = ? WHERE id = ?", (new_text, feedback_id))
        con.commit()
        con.close()
        
        return jsonify({"success": True, "message": "Feedback updated successfully"})
    
    except Exception as e:
        logError(5001, f"Error editing feedback: {str(e)}")
        return jsonify({"success": False, "message": "Error updating feedback"}), 500

# Route for deleting feedback
@app.route("/delete_feedback", methods=["POST"])
@limiter.limit("10 per minute")
def deleteFeedback():
    # Require login to access this functionality
    if 'user' not in session:
        return jsonify({"success": False, "message": "You must be logged in"}), 401
    
    # Validate CSRF token to prevent cross-site request forgery
    if 'csrf_token' not in request.form:
        return jsonify({"success": False, "message": "Invalid request"}), 400
    
    try:
        # Get feedback ID from request
        feedback_id = request.form.get("feedback_id")
        
        # Validate input
        if not feedback_id:
            return jsonify({"success": False, "message": "Invalid input"}), 400
        
        # Connect to database
        con = sql.connect("database_files/database.db")
        cur = con.cursor()
        
        # First check if the feedback belongs to the current user
        result = cur.execute("SELECT username FROM feedback WHERE id = ?", (feedback_id,)).fetchone()
        
        if not result:
            con.close()
            return jsonify({"success": False, "message": "Feedback not found"}), 404
            
        # Verify ownership - users can only delete their own feedback
        if result[0] != session['user']:
            con.close()
            return jsonify({"success": False, "message": "You can only delete your own feedback"}), 403
        
        # Delete the feedback
        cur.execute("DELETE FROM feedback WHERE id = ?", (feedback_id,))
        con.commit()
        con.close()
        
        return jsonify({"success": True, "message": "Feedback deleted successfully"})
    
    except Exception as e:
        logError(5002, f"Error deleting feedback: {str(e)}")
        return jsonify({"success": False, "message": "Error deleting feedback"}), 500

# ===============================
# Main Code - Application Startup
# ===============================

if __name__ == "__main__":
    # Set up security for sessions
    app.config["TEMPLATES_AUTO_RELOAD"] = True  # Reload templates without restarting server
    app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0  # Disable caching for development
    
    # Secure cookie settings
    app.config["SESSION_COOKIE_SECURE"] = True  # Only send cookies over HTTPS
    app.config["SESSION_COOKIE_HTTPONLY"] = True  # Prevent JavaScript from accessing cookies
    app.config["SESSION_COOKIE_SAMESITE"] = 'Lax'  # Restrict cookie sending to same site
    
        # should suppress the URL from giving out details that could be private
    from werkzeug.serving import WSGIRequestHandler
    
    class CustomRequestHandler(WSGIRequestHandler):
        def version_string(self):
            return ''  
    host = "0.0.0.0" 
    port = 8000
    
    print(f"\nServer running!")
    print(f"Access your Secure PWA at: http://localhost:{port}")
    print(f"Server is listening on {host}:{port}")
    print(f"Press CTRL+C to stop the server\n")
    
    # start the server
    app.run(debug=True, host=host, port=port, request_handler=CustomRequestHandler)
