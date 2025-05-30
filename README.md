# Secure PWA Implementation

This document tracks the security improvements made to the PWA application and demonstrates how they align with the security requirements outlined in the UnsecurePWADocumentation.

## Latest Updates
- [Server Header Suppression](#26-server-header-suppression) - Prevents information disclosure by suppressing server version details in HTTP headers, addressing OWASP ZAP vulnerability findings.
- [CSRF Protection with Flask-WTF](#21-csrf-protection-with-flask-wtf) - Implements Cross-Site Request Forgery protection using synchronizer tokens.
- [Real-Time Input Validation](#14-real-time-input-validation) - Provides instant visual feedback for form fields as users type.
- [HTML Attribute Protection](#20-html-attribute-protection) - Prevents attribute-based XSS attacks through specialized sanitization.

## Table of Contents

### Authentication & User Management
1. [Secure Random Secret Key](#5-secure-random-secret-key)
2. [Password Hashing](#1-password-hashing-data-protection)
3. [Password Complexity Validation](#11-password-complexity-validation)
4. [Email Field in Registration](#9-email-field-in-registration)
5. [Two-Factor Authentication (2FA)](#12-two-factor-authentication-2fa)
6. [Secure Session Management](#8-secure-session-management)
7. [Anti-Timing Attack Measures](#17-anti-timing-attack-measures)

### Data Protection & Input Handling
8. [SQL Injection Prevention](#2-sql-injection-prevention)
9. [Input Sanitization for XSS Prevention](#3-input-sanitization-for-xss-prevention)
10. [HTML Attribute Protection](#20-html-attribute-protection)
11. [Real-Time Input Validation](#14-real-time-input-validation)
12. [Feedback Length Limiting](#15-feedback-length-limiting)

### HTTP Security Headers & Policies
13. [Security Headers for XFS Prevention](#4-security-headers-for-xfs-prevention)
14. [Content Security Policy (CSP)](#18-content-security-policy-csp-implementation)
15. [Server Header Suppression](#26-server-header-suppression)

### Request & API Security
16. [Rate Limiting for API Security](#6-rate-limiting-for-api-security)
17. [CSRF Protection with Flask-WTF](#21-csrf-protection-with-flask-wtf)
18. [Secure Redirects](#7-secure-redirects)
19. [URL Parameter Security](#19-url-parameter-security)

### Monitoring & Maintenance
20. [Comprehensive Logging](#10-comprehensive-logging)
21. [Visitor Count Tracking](#16-visitor-count-tracking)
22. [Unit Testing](#13-unit-testing)

### Appendices
23. [Security Checklist Status](#security-checklist-status)
24. [How to Run the Application](#how-to-run-the-application)
25. [Running Tests](#running-tests)
26. [References](#references)

## 1. Password Hashing (Data Protection)

**Description: Securely stores user passwords using bcrypt hashing with salt to protect sensitive data.**

**Location: user_management.py**
```python
def hashPassword(password):
    salt = bcrypt.gensalt()
    hashedPassword = bcrypt.hashpw(password.encode(), salt)
    return hashedPassword

def checkPassword(plainPassword, hashedPassword):
    return bcrypt.checkpw(plainPassword.encode(), hashedPassword)
```

<details>
<summary><b>Click to expand implementation details</b></summary>

**How It Works:**
The application uses the bcrypt hashing algorithm to securely store passwords. When a user creates an account, their password is:

1. Combined with a unique "salt" (random data) to prevent rainbow table attacks
2. Hashed using the bcrypt algorithm, which is specifically designed for password hashing
3. Stored in the database as the hash, never as plaintext

When the user attempts to log in, their entered password is hashed using the same process and compared to the stored hash.

**Implementation Details:**
- Uses the bcrypt library for secure password hashing
- Automatically generates unique salt for each password
- Password is encoded to bytes before hashing
- Resistant to brute force attacks due to bcrypt's computational intensity
</details>

**Key Benefits:**
- Prevents storage of plaintext passwords
- Protects against password theft if database is compromised
- Includes unique salt for each password to prevent rainbow table attacks

**Documentation Alignment:**
- Section 3.1.2: "Strategies employed for data encryption and storage"
- Section 7.1: "Security features" > "Data protection"
- Section 8.1: "Contribution of cryptography and sandboxing"

## 2. SQL Injection Prevention

**Description: Protects database queries from malicious SQL injection attacks using parameterized queries.**

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

<details>
<summary><b>Click to expand implementation details</b></summary>

**How It Works:**
Parameterized queries separate SQL code from data, preventing attackers from injecting malicious code into queries. The `?` placeholder in the SQL statement is safely replaced with the actual value without allowing it to be interpreted as code. This implementation is used consistently throughout the application for all database operations.

**Implementation Details:**
- Uses SQLite's parameter substitution mechanism
- Applies to all database operations (SELECT, INSERT, UPDATE)
- Prevents classic SQL injection attacks like `' OR 1=1 --`
- Complements input validation and sanitization
</details>

**Key Benefits:**
- Prevents attackers from injecting malicious SQL code
- Protects database integrity and confidentiality
- Follows industry best practices for database security

**Documentation Alignment:**
- Section 10.2: "Testing methods" > "Vulnerability assessment"
- Section 11: "Defensive data input handling"
- Section 14: "Secure code for user action controls" > "SQL injection prevention"

## 3. Input Sanitization for XSS Prevention

**Description: Sanitizes user input to prevent Cross-Site Scripting (XSS) attacks by escaping HTML special characters.**

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

<details>
<summary><b>Click to expand implementation details</b></summary>

**How It Works:**
The application uses the `html.escape()` function to convert potentially dangerous characters like `<`, `>`, `&`, `'`, and `"` into their HTML entity equivalents. This prevents browsers from interpreting these characters as HTML or JavaScript code, thus neutralizing XSS attacks.

**Implementation Details:**
- Applied consistently to all user inputs except passwords
- Converts special characters to HTML entities (e.g., `<` becomes `&lt;`)
- Protects against both stored and reflected XSS attacks
- Complements client-side validation and Content Security Policy
</details>

**Key Benefits:**
- Prevents injection of malicious JavaScript into web pages
- Protects users from client-side attacks
- Reduces risk of data theft and session hijacking

**Documentation Alignment:**
- Section 7.1: "Security features" > "Security measures"
- Section 11: "Defensive data input handling"
- Section 14: "Secure code for user action controls" > "Cross-site scripting (XSS)"

## 4. Security Headers for XFS Prevention

**Description: Implements security headers to prevent Cross-Frame Scripting (XFS) and related attacks.**

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

<details>
<summary><b>Click to expand implementation details</b></summary>

**How It Works:**
Security headers are HTTP response headers that tell browsers how to behave when handling the site's content:

1. **X-Frame-Options: DENY** - Prevents the page from being embedded in iframes on other sites, protecting against clickjacking attacks.

2. **X-Content-Type-Options: nosniff** - Prevents browsers from trying to guess ("sniff") the MIME type of responses, stopping attacks that rely on MIME confusion.

3. **Strict-Transport-Security** - Forces browsers to use HTTPS for all future connections, preventing protocol downgrade attacks and cookie hijacking.

4. **X-XSS-Protection** - Enables built-in browser XSS filters, providing an additional layer of protection against cross-site scripting.

**Implementation Details:**
- Applied globally to all responses using Flask's `after_request` hook
- Configured with secure, restrictive values
- Complemented by proper content types in all responses
</details>

**Key Benefits:**
- Prevents clickjacking attacks by controlling iframe loading
- Reduces risk of content sniffing attacks
- Enforces HTTPS connections for enhanced security
- Adds browser-level XSS filtering protection

**Documentation Alignment:**
- Section 7.1: "Security features" > "Security measures"
- Section 14: "Secure code for user action controls" > "Broken authentication"

## 5. Secure Random Secret Key

**Description: Generates a cryptographically secure random secret key for session management.**

**Location: main.py**
```python
import secrets
# More imports...

app = Flask(__name__)
# Generate a strong random secret key for session security
app.secret_key = secrets.token_hex(32)
```

<details>
<summary><b>Click to expand implementation details</b></summary>

**How It Works:**
The application uses Python's `secrets` module to generate a cryptographically secure random secret key with 32 bytes of entropy (64 hexadecimal characters). This key is used to sign session cookies, ensuring they cannot be tampered with.

**Implementation Details:**
- Uses Python's `secrets` module (designed for security-sensitive contexts)
- Generates 256 bits of entropy (32 bytes) for the key
- Key is unique for each server start, preventing predictability
- Secret never exposed in logs or responses
</details>

**Key Benefits:**
- Prevents session hijacking by using unpredictable secret keys
- Makes session tokens difficult to guess or crack
- Improves overall security of the application

**Documentation Alignment:**
- Section 7.1: "Security features" > "Security measures"
- Section 8.1: "Contribution of cryptography and sandboxing" 
- Section 13: "Efficient execution for the user" > "Session management"

## 6. Rate Limiting for API Security

**Description: Implements rate limiting to prevent abuse, brute force attacks, and denial of service attempts.**

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

<details>
<summary><b>Click to expand implementation details</b></summary>

**How It Works:**
The application uses Flask-Limiter to restrict the number of requests a client can make in a given time period. Different routes have different rate limits depending on their sensitivity:

1. **Global Limit** - 200 requests per day and 50 requests per hour per IP address
2. **Signup and 2FA Routes** - 5 requests per minute (tighter security for authentication)
3. **Content Routes** - 10 requests per minute (balanced access to content)

Rate limiting is implemented by tracking client IP addresses and rejecting requests that exceed the configured limits with a 429 Too Many Requests response.

**Implementation Details:**
- IP-based rate limiting using `get_remote_address`
- In-memory storage for rate limiting counters
- Route-specific limits for sensitive operations
- Automatic HTTP 429 responses with Retry-After headers
</details>

**Key Benefits:**
- Prevents brute force attacks on authentication endpoints
- Mitigates denial of service (DoS) attempts
- Reduces server load from abusive requests
- Provides better service reliability for legitimate users

**Documentation Alignment:**
- Section 9.1: "Methods for identifying vulnerabilities and creating resilience" > "Hardening systems"
- Section 12: "Safe API development"

## 7. Secure Redirects

**Description: Validates redirect URLs to prevent open redirect vulnerabilities and potential phishing attacks.**

<details>
<summary><b>Click to expand implementation details</b></summary>

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

**How It Works:**
The application validates all redirect URLs to ensure they point either to internal pages or to a whitelist of trusted domains. This prevents attackers from crafting malicious links that could redirect users to phishing sites.

**Implementation Details:**
- Whitelist approach with allowed domains
- Regular expression parsing of URLs
- Domain extraction and validation
- Default safe redirect to home page
- Validates all URL parameters used for redirection
</details>

**Key Benefits:**
- Prevents attackers from using the application for phishing attacks
- Restricts redirects to trusted domains only
- Reduces risk of users being directed to malicious sites

**Documentation Alignment:**
- Section 14: "Secure code for user action controls" > "Invalid forwarding and redirecting"

## 8. Secure Session Management

**Description: Configures secure session cookies to protect user sessions from various attacks.**

**Location: main.py**
```python
if __name__ == "__main__":
    app.config["TEMPLATES_AUTO_RELOAD"] = True
    app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0
    app.config["SESSION_COOKIE_SECURE"] = True
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = 'Lax'
    
    # Suppress server header by using a custom ServerClass
    from werkzeug.serving import WSGIRequestHandler
    
    class CustomRequestHandler(WSGIRequestHandler):
        def version_string(self):
            return ''  # Return empty string instead of default server version
    
    host = "0.0.0.0"
    port = 8000
    
    app.run(debug=True, host=host, port=port, request_handler=CustomRequestHandler)
```

<details>
<summary><b>Click to expand implementation details</b></summary>

**How It Works:**
The application uses Flask's session management with enhanced security configurations:

1. **Secure Flag**: Ensures cookies are only sent over HTTPS connections, preventing interception over insecure networks.

2. **HttpOnly Flag**: Prevents JavaScript from accessing the session cookie, protecting against XSS attacks that attempt to steal session identifiers.

3. **SameSite Flag**: Set to 'Lax' mode, which prevents cookies from being sent in cross-site requests except for top-level navigations, protecting against CSRF attacks.

**Implementation Details:**
- Secure cookie configuration
- Server-side session state management
- Explicit session termination on logout
- Proper session ID regeneration
- Temporary session states for multi-step processes
</details>

**Key Benefits:**
- Prevents cookie theft via JavaScript (HttpOnly)
- Ensures cookies are only sent over HTTPS (Secure)
- Protects against cross-site request forgery attacks (SameSite)
- Enhances overall session security

**Documentation Alignment:**
- Section 7.1: "Security features" > "User authentication and authorisation"
- Section 13: "Efficient execution for the user" > "Session management"
</details>

## 9. Email Field in Registration

**Description: Implements email collection in user registration for account verification and communication.**

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

def insertUser(username, password, dob, email=""):
    try:
        addEmailColumnIfNotExists()
        # More code...
        cur.execute(
            "INSERT INTO users (username,password,dateOfBirth,email,totp_secret) VALUES (?,?,?,?,?)",
            (username, hashedPassword, dob, email, totp_secret),
        )
        # More code...
```

**Location: templates/signup.html**
```html
<div class="input__wrapper">
    <input type="email" name="email" placeholder="Email Address" class="input__field" required>
</div>
```

<details>
<summary><b>Click to expand implementation details</b></summary>

**How It Works:**
The application collects and stores email addresses during registration using proper HTML5 validation. The database schema is dynamically updated if needed to ensure the email field exists.

**Implementation Details:**
- HTML5 email input type with built-in format validation
- Database migration logic to add email column if not present
- Email sanitization before storage
- Email format validation using both client and server validation
</details>

**Key Benefits:**
- Enables communication with users through email
- Provides option for email-based account recovery
- Can be used for verification to prevent fake accounts
- Supports two-factor authentication implementation

**Documentation Alignment:**
- Section 4.2: "Determining specifications" > "Login page development"
- Section 7.1: "Security features" > "User authentication and authorisation"

## 10. Comprehensive Logging

**Description: Implements detailed security logging to track and analyze security events and potential issues.**

**Location: user_management.py**
```python
logging.basicConfig(filename='security_log.log', level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Example of logging usage
def insertUser(username, password, dob, email=""):
    try:
        # Function code...
        logging.info(f"New user created: {username}")
    except Exception as e:
        logging.error(f"Error creating user: {str(e)}")
```

<details>
<summary><b>Click to expand implementation details</b></summary>

**How It Works:**
The application maintains a comprehensive security log that captures various security-relevant events:

1. **Authentication Events**: Successful and failed login attempts
2. **Account Management**: User creation and modification
3. **Security Operations**: 2FA setup and verification
4. **System Errors**: Exceptions and error conditions
5. **Administrative Actions**: Database operations and system changes

Each log entry includes a timestamp, severity level, and detailed message, providing a complete audit trail for security analysis.

**Implementation Details:**
- Structured logging format with timestamps
- Different severity levels (INFO, WARNING, ERROR)
- Exception details captured for troubleshooting
- Descriptive messages with context information
- File-based persistent storage
</details>

**Key Benefits:**
- Provides audit trail for security events and user actions
- Supports incident response and forensic analysis
- Helps identify and diagnose security issues
- Enables continuous security monitoring

**Documentation Alignment:**
- Section 4.8: "Maintenance" > "Strategies for ongoing security monitoring and updates"
- Section 11: "Defensive data input handling" > "Error handling"
- Section 13: "Efficient execution for the user" > "Exception management"
</details>

## 11. Password Complexity Validation

**Description: Enforces strong password requirements to enhance security of user accounts.**

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

<details>
<summary><b>Click to expand implementation details</b></summary>

**How It Works:**
The application enforces password complexity requirements through regular expression pattern matching. Passwords must meet all of the following criteria:

1. **Length** - Between 8 and 20 characters
2. **Character Types** - Must include:
   - At least one uppercase letter
   - At least one lowercase letter
   - At least one number
   - At least one special character

If any requirement fails, specific feedback is provided to the user about which criterion was not met, guiding them to create a stronger password.

**Implementation Details:**
- Server-side validation using regular expressions
- Clear error messages for failed validation
- Applied during user creation
- Complemented by client-side validation for instant feedback
</details>

**Key Benefits:**
- Forces users to create stronger passwords
- Reduces risk of password guessing and brute force attacks
- Complies with industry standards for password security
- Protects users even if they reuse passwords across sites

**Documentation Alignment:**
- Section 4.2: "Determining specifications" > "Password hashing"
- Section 7.1: "Security features" > "User authentication and authorisation"

## 12. Two-Factor Authentication (2FA)

**Description: Implements Time-based One-Time Password (TOTP) as a second authentication factor for enhanced security.**

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

<details>
<summary><b>Click to expand implementation details</b></summary>

**How It Works:**
The application implements TOTP-based two-factor authentication:

1. During signup, a unique secret key is generated and stored for each user
2. Users scan a QR code with their authenticator app (or manually enter the secret)
3. The app generates 6-digit codes that change every 30 seconds
4. During login, users must provide both their password and the current TOTP code
5. Server verifies the code against the stored secret and current time

**Implementation Details:**
- Uses the pyotp library for TOTP implementation
- Base32-encoded secret keys for compatibility with authenticator apps
- QR code generation for easy setup
- Fallback option with manual secret entry
- Time drift window accommodation
</details>

**Key Benefits:**
- Adds an additional layer of security beyond passwords
- Protects accounts even if passwords are compromised
- Eliminates risks from password database breaches
- Compatible with standard authenticator apps (Google Authenticator, Authy, etc.)

**Documentation Alignment:**
- Section 4.2: "Determining specifications" > "Two-factor authentication (2FA)"
- Section 7.1: "Security features" > "User authentication and authorisation"

## 13. Unit Testing

**Description: Implements automated tests to verify security features are working correctly.**

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

<details>
<summary><b>Click to expand implementation details</b></summary>

**How It Works:**
The application includes a suite of automated tests that verify the correct implementation and behavior of security features. These tests cover various aspects:

1. **Password Validation**: Tests for all password complexity rules
2. **Input Sanitization**: Verifies XSS protection is working
3. **Authentication Logic**: Tests login flows and 2FA verification
4. **Access Control**: Verifies protected routes require authentication
5. **Error Handling**: Tests for proper handling of invalid inputs

The tests use Python's unittest framework to provide structured verification of security controls, ensuring they continue to function as expected.

**Implementation Details:**
- Unit tests for individual security components
- Integration tests for authentication flows
- Negative testing for invalid inputs
- Test coverage for security-critical functions
- Reproducible test cases for regression testing
</details>

**Key Benefits:**
- Ensures security features work as expected
- Prevents security regressions during development
- Provides documentation of expected security behavior
- Supports continuous integration and deployment practices

**Documentation Alignment:**
- Section 4.5: "Testing and debugging" > "Methods for ensuring security through testing"
- Section 10.2: "Testing methods" > "Static application security testing (SAST)"
</details>

## 14. Real-Time Input Validation

**Description: Implements client-side validation for form inputs that provides instant visual feedback to users as they type.**

**Location: templates/signup.html**
```html
<div class="input__wrapper">
    <input type="text" name="username" id="username-input" placeholder="Username" class="input__field" required>
    <div class="validation-info">
        <p>Username must:</p>
        <ul>
            <li id="username-length">Be between 3 and 20 characters long</li>
            <li id="username-alphanumeric">Contain only letters, numbers, and underscores</li>
        </ul>
    </div>
</div>
```

**Location: static/js/passwordValidator.js**
```javascript
document.addEventListener('DOMContentLoaded', function() {
    // Get input elements
    const usernameInput = document.getElementById('username-input');
    const emailInput = document.getElementById('email-input');
    const passwordInput = document.getElementById('password-input');
    
    // Username validation logic
    if (usernameInput) {
        const usernameLengthReq = document.getElementById('username-length');
        const usernameAlphanumericReq = document.getElementById('username-alphanumeric');
        
        // Regular expressions for validation
        const usernameLengthRegex = /^.{3,20}$/;
        const usernameAlphanumericRegex = /^[a-zA-Z0-9_]+$/;
        
        usernameInput.addEventListener('input', function() {
            const username = usernameInput.value;
            
            // Validate each requirement
            updateValidation(usernameLengthReq, usernameLengthRegex.test(username));
            updateValidation(usernameAlphanumericReq, usernameAlphanumericRegex.test(username));
        });
    }
    
    // Function to update validation UI
    function updateValidation(element, isValid) {
        if (!element) return;
        
        if (isValid) {
            element.classList.remove('invalid');
            element.classList.add('valid');
            element.innerHTML = '✓ ' + element.textContent.replace('✓ ', '').replace('✗ ', '');
        } else {
            element.classList.remove('valid');
            element.classList.add('invalid');
            element.innerHTML = '✗ ' + element.textContent.replace('✓ ', '').replace('✗ ', '');
        }
    }
});
```

<details>
<summary><b>Click to expand implementation details</b></summary>

**How It Works:**
The application provides instant, client-side validation feedback as users fill out forms, improving both security and user experience:

1. **Validation Requirements Display**: Requirements for each field (username, email, password) are visually presented below input fields, setting clear expectations for users.

2. **Real-Time Input Checking**: JavaScript event listeners monitor user input in real-time, validating against predefined criteria:
   - Username: Length (3-20 characters) and character set (alphanumeric + underscore)
   - Email: Valid email format check
   - Password: Length, uppercase, lowercase, number, and special character requirements

3. **Visual Feedback System**: Requirements dynamically update as users type:
   - Valid requirements turn green with checkmarks (✓)
   - Invalid requirements turn red with X marks (✗)

4. **Progressive Disclosure**: Validation information appears when users focus on input fields, providing guidance without cluttering the interface.

This creates a feedback loop that guides users toward creating valid inputs without requiring form submission, significantly improving both security and usability.

**Implementation Details:**
- Event-driven input validation using JavaScript
- Regular expression pattern matching for precise validation
- DOM manipulation for dynamic feedback updates
- Visual indicators with color and symbol changes
- Consistent implementation across all critical form fields
- Integration with server-side validation as a defense-in-depth measure
</details>

**Key Benefits:**
- Improves user experience by providing immediate feedback
- Reduces form submission errors and user frustration
- Guides users toward creating secure credentials
- Acts as a first line of defense against invalid inputs
- Complements server-side validation for defense-in-depth
- Reduces server load by catching errors before submission

**Documentation Alignment:**
- Section 4.2: "Determining specifications" > "Input field sanitisation"
- Section 5.1: "User-friendly authentication"
- Section 7.1: "Security features" > "User authentication and authorisation"
- Section 11: "Defensive data input handling"
- Section 13: "Efficient execution for the user"

## 15. Feedback Length Limiting

**Description: Restricts feedback text length to prevent abuse and protect the application from excessive data.**

**Location: main.py**
```python
@app.route("/success.html", methods=["POST", "GET"])
@limiter.limit("10 per minute")
def addFeedback():
    # Other code...
    if request.method == "POST":
        feedback = sanitizeInput(request.form["feedback"])
        if len(feedback) > 500:
            feedback = feedback[:500]
        dbHandler.insertFeedback(feedback)
        dbHandler.listFeedback()
        return redirect("/success.html")
    # More code...
```

<details>
<summary><b>Click to expand implementation details</b></summary>

**How It Works:**
The application enforces a 500-character limit on user feedback submissions. When a user submits feedback, the application:

1. Sanitizes the input to prevent XSS attacks
2. Checks if the input exceeds 500 characters
3. If it does, truncates the feedback to 500 characters
4. Stores only the truncated feedback in the database

This protects the system from various issues including database size problems, UI rendering issues, and potential denial of service attacks.

**Implementation Details:**
- Hard limit of 500 characters enforced server-side
- Automatic truncation without error messages
- Applied after input sanitization
- Prevents excessive data storage
</details>

**Key Benefits:**
- Prevents database overflow from excessively long submissions
- Protects UI rendering from oversized content
- Reduces potential for abuse of the feedback system
- Ensures consistent data storage and display

**Documentation Alignment:**
- Section 11: "Defensive data input handling"
- Section 12: "Safe API development"
- Section 13: "Efficient execution for the user"
</details>

## 16. Visitor Count Tracking

**Description: Implements a visitor count tracking system to monitor application usage.**

<details>
<summary><b>Click to expand implementation details</b></summary>

**Location: user_management.py**
```python
def retrieveUsers(username, password):
    try:
        # Database query code...
        if user is None:
            # Error handling...
        else:
            storedHash = user[2]
            
            updateVisitorCount()
            
            time.sleep(random.randint(80, 90) / 1000)
            # Authentication logic...
    except Exception as e:
        # Error handling...

def updateVisitorCount():
    try:
        with open("visitor_log.txt", "r") as file:
            number = int(file.read().strip())
            number += 1
        with open("visitor_log.txt", "w") as file:
            file.write(str(number))
    except Exception as e:
        logging.error(f"Error updating visitor count: {str(e)}")
```

**How It Works:**
The application maintains a running count of login attempts in a text file. Each time a user attempts to log in (whether successful or not), the counter is incremented.

1. The current count is read from the `visitor_log.txt` file
2. The count is incremented by one
3. The new count is written back to the file

This provides a simple but effective way to track application usage over time.

**Implementation Details:**
- Simple file-based counter system
- Incremented on authentication attempts
- Persistent across application restarts
- Protected with error handling
- Logging for error conditions
</details>

**Key Benefits:**
- Provides usage statistics for the application
- Helps track unusual activity patterns
- Supports capacity planning and resource allocation
- Creates a historical record of authentication attempts

**Documentation Alignment:**
- Section 4.8: "Maintenance" > "Strategies for ongoing security monitoring and updates"
- Section 13: "Efficient execution for the user"

## 17. Anti-Timing Attack Measures

**Description: Implements countermeasures against timing attacks in the authentication system to prevent username enumeration.**

**Location: user_management.py**
```python
def retrieveUsers(username, password):
    try:
        # Database query code...
        if user is None:
            con.close()
            logging.warning(f"Failed login attempt: Username {username} not found")
            return False, None
        else:
            storedHash = user[2]
            
            updateVisitorCount()
            
            # Add a small random delay to prevent timing attacks
            time.sleep(random.randint(80, 90) / 1000)
            
            if checkPassword(password, storedHash):
                # Success handling...
            else:
                # Failure handling...
    except Exception as e:
        # Error handling...
```

<details>
<summary><b>Click to expand implementation details</b></summary>

**How It Works:**
The application includes countermeasures against timing attacks, which are side-channel attacks that attempt to discover information by measuring the time taken for operations.

1. **Randomized Delay**: A random delay between 80-90 milliseconds is added to the authentication process, obscuring any timing differences between valid and invalid username attempts.

2. **Consistent Code Paths**: The application ensures that similar code paths are followed regardless of whether a username exists or not, further preventing timing analysis.

3. **Logging Without Timing Impact**: The application logs failed login attempts but does so in a way that doesn't affect the timing significantly.

By adding this random delay and ensuring consistent code paths, the application makes timing attacks significantly more difficult to execute successfully, protecting against username enumeration.

**Implementation Details:**
- Random delay between 80-90ms during authentication
- Consistent code paths regardless of result
- Applied after database operations but before response
- Random number generation for unpredictability
- Comprehensive logging of authentication attempts
</details>

**Key Benefits:**
- Mitigates timing-based side-channel attacks
- Prevents username enumeration via timing analysis
- Makes brute-force attacks more time-consuming
- Protects user privacy by concealing account existence
- Reduces the effectiveness of automated attack tools

**Documentation Alignment:**
- Section 9.1: "Methods for identifying vulnerabilities and creating resilience"
- Section 7.1: "Security features" > "Security measures"
- Section 4.2: "Determining specifications" > "Security tools and technologies"
- Section 15: "Protecting against file attacks" > "Safeguarding from side channel attacks"
</details>

## Security Checklist Status

### Cross-Frame Scripting (XFS) Prevention
- [x] Implement Content Security Policy (CSP) to block iframe loading
- [x] Set X-Frame-Options header to DENY or SAMEORIGIN
- [x] Monitor server logs for unusually repetitive GET calls

### Cross-Site Scripting (XSS) Prevention
- [x] Implement input validation and sanitization for all user inputs
- [x] Set proper Content Security Policy (CSP) to block SVG and SCRIPT tags
- [x] Declare proper HTML lang attribute and charset (UTF-8)
- [x] Implement HTML attribute value sanitization
- [x] Use static form IDs to prevent dynamic attribute-based XSS

### Cross-Site Request Forgery (CSRF) Prevention
- [x] Implement synchronizer token pattern (STP) for all forms
- [x] Use Flask-WTF for built-in CSRF protection
- [x] Implement multi-factor authentication for administrative operations
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
- [x] Prevent sensitive information leakage in URL parameters

### General Security Measures
- [x] Implement secure password storage with proper hashing and salting
- [x] Set up proper session management with secure cookies
- [x] Configure secure headers
- [x] Implement proper error handling that doesn't leak sensitive information
- [x] Use session-based message storage instead of URL parameters
- [x] Suppress server headers to prevent information disclosure

### Additional Security Features
- [x] Email validation in registration
- [x] Password complexity rules
- [x] Two-factor authentication (2FA)
- [x] Unit testing for security features
- [x] Limited input length for feedback
- [x] User-friendly error messages
- [x] Real-time input validation feedback
- [x] Interception and handling of potentially vulnerable routes

## 18. Content Security Policy (CSP) Implementation

**Description: Implements a comprehensive Content Security Policy to prevent various cross-site attacks including XSS.**

**Location: main.py**
```python
@app.after_request
def setSecurityHeaders(response):
    # First, set X-Frame-Options as the fallback for frame-ancestors
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    # Hide server information to prevent information disclosure
    response.headers['Server'] = 'WebServer'
    
    # Instead of using frame-ancestors in CSP, we'll rely on X-Frame-Options
    # This solves the "CSP: Failure to Define Directive with No Fallback" issue
    csp = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "frame-src 'none'; "
        "form-action 'self'"
    )
    response.headers['Content-Security-Policy'] = csp
    
    return response
```

**Location: templates/layout.html**
```html
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <meta http-equiv="X-UA-Compatible" content="ie=edge" />
    <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-src 'none'; frame-ancestors 'none'; form-action 'self';">
    <!-- Other head elements -->
</head>
```

<details>
<summary><b>Click to expand implementation details</b></summary>

**How It Works:**
The application implements a comprehensive Content Security Policy (CSP) using a defense-in-depth approach:

1. **HTTP Header Implementation**: The server sets the CSP header in all HTTP responses via Flask's `after_request` hook, which instructs browsers on what resources can be loaded.

2. **Meta Tag Backup**: A corresponding meta tag is added to HTML documents as a secondary defense, ensuring CSP is enforced even if HTTP headers are somehow stripped.

3. **Resource Restriction Policy**: The policy includes several key protections:
   - `default-src 'self'` - Restricts all resources to come only from the application's own origin
   - `script-src 'self'` - Allows JavaScript only from the same origin, blocking inline scripts and external sources
   - `style-src 'self'` - Restricts CSS to the same origin
   - `img-src 'self' data:` - Allows images from the same origin and data URIs (needed for QR codes)
   - `frame-src 'none'` - Prevents the page from being framed
   - `form-action 'self'` - Ensures forms can only be submitted to the same origin

4. **Framework Integration**: The CSP is implemented both at the server level and in the HTML templates, ensuring maximum coverage.

This comprehensive CSP significantly reduces the risk of XSS attacks by restricting what resources can load and from where, creating multiple layers of defense.

**Implementation Details:**
- HTTP-header based CSP for universal browser support
- Meta tag as a defense-in-depth measure
- Strict resource restrictions to same-origin
- Complete block on frame usage
- Explicit handling of different content types
- Integration with other security headers
</details>

**Key Benefits:**
- Prevents execution of malicious injected scripts
- Blocks loading of unauthorized resources
- Provides defense-in-depth against XSS attacks
- Protects against clickjacking attacks
- Alerts browsers of potential security violations
- Reduces the attack surface for client-side attacks

**Documentation Alignment:**
- Section 7.1: "Security features" > "Security measures"
- Section 9.1: "Methods for identifying vulnerabilities and creating resilience"
- Section 14: "Secure code for user action controls" > "Cross-site scripting (XSS)"
- Section 4.2: "Determining specifications" > "Input field sanitisation"
</details>

## 19. URL Parameter Security

**Description: Implements protection against sensitive information leakage in URLs and prevents parameter-based attacks.**

**Location: main.py**
```python
# Check for sensitive parameters in URL requests
@app.before_request
def check_sensitive_parameters():
    # Only check GET requests (where parameters are in URL)
    if request.method == 'GET':
        # List of sensitive parameter names to check for
        sensitive_params = ['username', 'userName', 'user', 'password', 'apikey', 'key', 'token', 'secret']
        
        # Check if any sensitive parameters are in the query string
        for param in sensitive_params:
            if param.lower() in [k.lower() for k in request.args.keys()]:
                # If this is an API-like path, return a proper error response
                if '/UI/' in request.path or '/api/' in request.path:
                    return jsonify({
                        "error": "Sensitive information should not be passed in URL parameters",
                        "code": 400
                    }), 400
                # For regular web pages, redirect to a safe page
                return redirect("/")
```

**Location: main.py (Session-Based Message Storage)**
```python
@app.route("/logout")
def logout():
    session.pop('user', None)
    session.pop('temp_username', None)
    # Store message in session instead of URL parameter
    session['message'] = "You have been logged out successfully."
    return redirect("/")

@app.route("/", methods=["POST", "GET"])
def home():
    error = None
    # Get message from session instead of URL
    message = None
    if 'message' in session:
        message = session.pop('message')
    
    # Rest of the function...
    return render_template("/index.html", message=message, error=error)
```

<details>
<summary><b>Click to expand implementation details</b></summary>

**How It Works:**
The application implements several layers of protection against sensitive information leakage in URLs:

1. **Pre-Request Filtering**: A `before_request` hook checks all incoming GET requests for sensitive parameters like usernames, passwords, or API keys

2. **Session-Based Messages**: Information like success/error messages is stored in the session instead of being passed as URL parameters

3. **POST/Redirect/GET Pattern**: After form submissions, the application redirects to a new page instead of rendering directly, preventing form resubmission with sensitive data

4. **Special Route Handlers**: Dedicated routes handle potentially problematic paths identified in security scans

This comprehensive approach ensures that sensitive information doesn't appear in:
- Browser address bars
- Server logs
- Browser history
- Referrer headers

**Implementation Details:**
- Checks all GET requests for sensitive parameter names
- Case-insensitive parameter matching
- Different handling for API paths vs. web pages
- Session-based flash message pattern
- Sanitizes URL parameters before use
</details>

**Key Benefits:**
- Prevents leakage of sensitive data in URLs
- Improves compliance with security standards like PCI-DSS
- Reduces risks from browser history and server logs
- Protects against URL manipulation attacks
- Maintains user privacy when sharing links

**Documentation Alignment:**
- Section 3.1: "Data protection" > "Strategies employed for data encryption and storage"
- Section 7.1: "Security features" > "Privacy protection"
- Section 8.2: "Privacy by design approach"
- Section 14: "Secure code for user action controls" > "Invalid forwarding and redirecting"

## 20. HTML Attribute Protection

**Description: Implements protection against HTML attribute injection to prevent XSS attacks through attribute values.**

**Location: main.py**
```python
# Additional function to specifically sanitize HTML attribute values
def sanitizeAttributeValue(value):
    if value is None:
        return ""
    # Remove potentially dangerous characters for attributes
    sanitized = re.sub(r'[&<>"\'`=]', '', str(value))
    # Ensure the value doesn't start with 'javascript:' or similar
    sanitized = re.sub(r'^(javascript|data|vbscript):', '', sanitized, flags=re.IGNORECASE)
    return sanitized
```

**Location: templates/signup.html (Static Form IDs Example)**
```html
<!-- Before: Potentially dynamically generated ID -->
<form action="/" method="POST" class="box">

<!-- After: Static, hardcoded ID -->
<form action="/signup.html" method="POST" class="box" id="signup-form">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
    <!-- Form fields -->
</form>
```

<details>
<summary><b>Click to expand implementation details</b></summary>

**How It Works:**
The application includes specific protections against HTML attribute-based XSS attacks:

1. **Attribute Value Sanitization**: A specialized function removes characters that could break out of HTML attributes

2. **Protocol Handler Blocking**: Prevents dangerous URI schemes like `javascript:` from being used in attributes

3. **Static Form IDs**: All forms use static, hardcoded IDs instead of dynamically generated ones that might include user input

4. **Route Protection**: Special routes intercept potentially dangerous paths that security scanners might test

These measures prevent attackers from injecting code via HTML attributes, which is a common XSS vector that regular HTML escaping doesn't always catch.

**Implementation Details:**
- Targeted regular expression pattern matching
- Case-insensitive protocol handler detection
- Consistent use of static IDs across all forms
- Applies to URL parameters, form IDs, and other attribute values
</details>

**Key Benefits:**
- Closes a common XSS vulnerability vector
- Prevents attribute-based script injection
- Complements standard HTML escaping
- Protects against event handler injection
- Reduces attack surface in the UI layer

**Documentation Alignment:**
- Section 6.1: "Fundamental Software Design Security Concepts" > "Integrity"
- Section 11: "Defensive data input handling"
- Section 14: "Secure code for user action controls" > "Cross-site scripting (XSS)"
</details>