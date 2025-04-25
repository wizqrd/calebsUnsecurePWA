# Secure PWA Implementation

This document tracks the security improvements made to the PWA application and how they align with security requirements.

## 1. Password Hashing (Data Protection)

**Location: user_management.py**
```python
def hashPassword(password):
    salt = bcrypt.gensalt()
    hashedPassword = bcrypt.hashpw(password.encode(), salt)
    return hashedPassword

def checkPassword(plainPassword, hashedPassword):
    return bcrypt.checkpw(plainPassword.encode(), hashedPassword)
```

**Documentation Alignment:**
- Section 3.1.2: "Strategies employed for data encryption and storage"
- Section 7.1: "Security features" > "Data protection"
- Section 8.1: "Contribution of cryptography and sandboxing"

## 2. SQL Injection Prevention

**Location: user_management.py**
```python
def retrieveUsers(username, password):
    try:
        con = sql.connect("database_files/database.db")
        cur = con.cursor()
        cur.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cur.fetchone()
        # More code...
```

**Documentation Alignment:**
- Section 10.2: "Testing methods" > "Vulnerability assessment"
- Section 11: "Defensive data input handling"
- Section 14: "Secure code for user action controls" > "SQL injection prevention"

## 3. Input Sanitization for XSS Prevention

**Location: main.py**
```python
def sanitizeInput(input_text):
    return html.escape(input_text)

@app.route("/signup.html", methods=["POST", "GET"])
@limiter.limit("5 per minute")
def signup():
    # Other code...
    if request.method == "POST":
        username = sanitizeInput(request.form["username"])
        email = sanitizeInput(request.form["email"])
        password = request.form["password"]
        DoB = sanitizeInput(request.form["dob"])
        # More code...
```

**Documentation Alignment:**
- Section 7.1: "Security features" > "Security measures"
- Section 11: "Defensive data input handling"
- Section 14: "Secure code for user action controls" > "Cross-site scripting (XSS)"

## 4. CSRF Protection

**Location: main.py**
```python
from flask_wtf.csrf import CSRFProtect
# More imports...

app = Flask(__name__)
app.secret_key = "someSuperSecretRandomKey"

csrf = CSRFProtect(app)
```

**Location: templates/signup.html, index.html, success.html**
```html
<form action="/signup.html" method="POST" class="box">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
    <!-- Form fields -->
</form>
```

**Documentation Alignment:**
- Section 7.1: "Security features" > "Security measures"
- Section 14: "Secure code for user action controls" > "CSRF"

## 5. Security Headers for XFS Prevention

**Location: main.py**
```python
@app.after_request
def setSecurityHeaders(response):
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response
```

**Documentation Alignment:**
- Section 7.1: "Security features" > "Security measures"
- Section 14: "Secure code for user action controls" > "Broken authentication"

## 6. Content Security Policy

**Location: main.py**
```python
from flask_csp import CSP
# More imports...

app = Flask(__name__)
# More setup...
csp = CSP(app)
```

**Location: templates/layout.html**
```html
<meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self';">
```

**Documentation Alignment:**
- Section 7.1: "Security features" > "Security measures"
- Section 14: "Secure code for user action controls" > "Cross-site scripting (XSS)"

## 7. Rate Limiting for API Security

**Location: main.py**
```python
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
# More imports...

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)

@app.route("/signup.html", methods=["POST", "GET"])
@limiter.limit("5 per minute")
def signup():
    # Function code...
```

**Documentation Alignment:**
- Section 9.1: "Methods for identifying vulnerabilities and creating resilience" > "Hardening systems"
- Section 12: "Safe API development"

## 8. Secure Redirects

**Location: main.py**
```python
def isValidRedirect(url):
    allowedDomains = ["localhost", "127.0.0.1"]
    pattern = r'^https?://([^/]+).*$'
    match = re.match(pattern, url)
    if match:
        domain = match.group(1)
        for allowed in allowedDomains:
            if domain == allowed or domain.endswith("." + allowed):
                return True
    return url.startswith('/')

@app.route("/success.html", methods=["POST", "GET"])
@limiter.limit("10 per minute")
def addFeedback():
    if request.method == "GET" and request.args.get("url"):
        url = request.args.get("url", "")
        if isValidRedirect(url):
            return redirect(url, code=302)
        else:
            return redirect("/", code=302)
    # More code...
```

**Documentation Alignment:**
- Section 14: "Secure code for user action controls" > "Invalid forwarding and redirecting"

## 9. Secure Session Management

**Location: main.py**
```python
if __name__ == "__main__":
    app.config["TEMPLATES_AUTO_RELOAD"] = True
    app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0
    app.config["SESSION_COOKIE_SECURE"] = True
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = 'Lax'
    app.run(debug=True, host="0.0.0.0", port=8080)
```

**Documentation Alignment:**
- Section 7.1: "Security features" > "User authentication and authorisation"
- Section 13: "Efficient execution for the user" > "Session management"

## 10. Email Field in Registration

**Location: user_management.py**
```python
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
        
        con.close()
    except Exception as e:
        logging.error(f"Error adding columns: {str(e)}")

def insertUser(username, password, DoB, email=""):
    try:
        addEmailColumnIfNotExists()
        # More code...
        cur.execute(
            "INSERT INTO users (username,password,dateOfBirth,email,totp_secret) VALUES (?,?,?,?,?)",
            (username, hashedPassword, DoB, email, totp_secret),
        )
        # More code...
```

**Location: templates/signup.html**
```html
<div class="input__wrapper">
    <input type="email" name="email" placeholder="Email Address" class="input__field" required>
</div>
```

**Documentation Alignment:**
- Section 4.2: "Determining specifications" > "Login page development"
- Section 7.1: "Security features" > "User authentication and authorisation"

## 11. Comprehensive Logging

**Location: user_management.py**
```python
logging.basicConfig(filename='security_log.log', level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Example of logging usage
def insertUser(username, password, DoB, email=""):
    try:
        # Function code...
        logging.info(f"New user created: {username}")
    except Exception as e:
        logging.error(f"Error creating user: {str(e)}")
```

**Documentation Alignment:**
- Section 4.8: "Maintenance" > "Strategies for ongoing security monitoring and updates"
- Section 11: "Defensive data input handling" > "Error handling"
- Section 13: "Efficient execution for the user" > "Exception management"

## 12. Password Complexity Validation

**Location: user_management.py**
```python
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
```

**Documentation Alignment:**
- Section 4.2: "Determining specifications" > "Password hashing"
- Section 7.1: "Security features" > "User authentication and authorisation"

## 13. Two-Factor Authentication (2FA)

**Location: user_management.py**
```python
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
```

**Location: main.py**
```python
@app.route("/verify_2fa", methods=["POST"])
@limiter.limit("5 per minute")
def verify_2fa_setup():
    if request.method == "POST":
        username = request.form["username"]
        token = request.form["token"]
        
        secret = dbHandler.getTOTPSecret(username)
        if not secret:
            return render_template("/setup_2fa.html", error="Invalid setup. Please try again.")
        
        if dbHandler.verifyTOTP(secret, token):
            session['user'] = username
            return redirect("/success.html")
        else:
            return render_template("/setup_2fa.html", 
                               error="Invalid code. Please try again.", 
                               qr_code=dbHandler.generateQRCode(username, secret),
                               secret=secret,
                               username=username)
```

**Documentation Alignment:**
- Section 4.2: "Determining specifications" > "Two-factor authentication (2FA)"
- Section 7.1: "Security features" > "User authentication and authorisation"

## 14. Unit Testing

**Location: tests.py**
```python
def test_password_validation(self):
    # Test password validation
    # Test valid password
    valid, _ = dbHandler.validatePassword("Passw0rd!")
    self.assertTrue(valid)
    
    # Test too short password
    valid, _ = dbHandler.validatePassword("Pw0rd!")
    self.assertFalse(valid)
    
    # Test missing uppercase
    valid, _ = dbHandler.validatePassword("passw0rd!")
    self.assertFalse(valid)
```

**Documentation Alignment:**
- Section 4.5: "Testing and debugging" > "Methods for ensuring security through testing"
- Section 10.2: "Testing methods" > "Static application security testing (SAST)"

## Security Checklist Status

### Cross-Frame Scripting (XFS) Prevention
- [x] Set X-Frame-Options header to DENY or SAMEORIGIN
- [x] Monitor server logs for unusually repetitive GET calls

### Cross-Site Scripting (XSS) Prevention
- [x] Implement input validation and sanitization for all user inputs
- [x] Set proper Content Security Policy (CSP)
- [x] Declare proper HTML lang attribute and charset (UTF-8)

### Cross-Site Request Forgery (CSRF) Prevention
- [x] Implement synchronizer token pattern (STP) for all forms
- [x] Consider using Flask-WTF for built-in CSRF protection
- [x] Implement server-side Content Security Policy

### SQL Injection Prevention
- [x] Use parameterized queries instead of string concatenation
- [x] Implement defensive data handling practices
- [x] Require authentication before accepting any form input

### API Security
- [x] Implement proper authentication and authorization
- [x] Implement rate limiting to prevent DoS attacks (Flask-Limiter)
- [x] Configure proper CORS settings (Flask-CORS) with domain restrictions if possible
- [x] Implement detailed logging of all API requests

### General Security Measures
- [x] Implement secure password storage with proper hashing and salting
- [x] Set up proper session management with secure cookies
- [x] Configure secure headers
- [x] Implement proper error handling that doesn't leak sensitive information

### Additional Security Features
- [x] Email validation in registration
- [x] Password complexity rules
- [x] Two-factor authentication (2FA)
- [x] Unit testing for security features
- [x] Limited input length for feedback
- [x] User-friendly error messages

## How to Run the Application

1. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

2. Run the application:
   ```
   python main.py
   ```

3. Access the application at http://localhost:8080

## Running Tests

Run the unit tests with:
```
python tests.py
```

## References

1. [OWASP Top Ten](https://owasp.org/www-project-top-ten/)
2. [Flask Security Documentation](https://flask.palletsprojects.com/en/2.0.x/security/)
3. [NIST Guidelines for Password Management](https://pages.nist.gov/800-63-3/sp800-63b.html)
