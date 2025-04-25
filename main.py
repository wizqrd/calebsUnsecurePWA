from flask import Flask
from flask import render_template
from flask import request
from flask import redirect
from flask import session
from flask import make_response
from flask_wtf.csrf import CSRFProtect
from flask_csp import CSP
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import html
import re
import user_management as dbHandler

# Code snippet for logging a message
# app.logger.critical("message")

app = Flask(__name__)
app.secret_key = "234098572435234"

csrf = CSRFProtect(app)
csp = CSP(app)
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)

def sanitizeInput(input_text):
    return html.escape(input_text)

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
    if 'user' not in session:
        return redirect("/")
        
    if request.method == "GET" and request.args.get("url"):
        url = request.args.get("url", "")
        if isValidRedirect(url):
            return redirect(url, code=302)
        else:
            return redirect("/", code=302)
    if request.method == "POST":
        feedback = sanitizeInput(request.form["feedback"])
        if len(feedback) > 500:  # Limit feedback length
            feedback = feedback[:500]
        dbHandler.insertFeedback(feedback)
        dbHandler.listFeedback()
        return render_template("/success.html", state=True, value=session['user'], message="Feedback submitted successfully!")
    else:
        dbHandler.listFeedback()
        return render_template("/success.html", state=True, value=session['user'])


@app.route("/signup.html", methods=["POST", "GET"])
@limiter.limit("5 per minute")
def signup():
    error = None
    if request.method == "GET" and request.args.get("url"):
        url = request.args.get("url", "")
        if isValidRedirect(url):
            return redirect(url, code=302)
        else:
            return redirect("/", code=302)
    if request.method == "POST":
        username = sanitizeInput(request.form["username"])
        email = sanitizeInput(request.form["email"])
        password = request.form["password"]
        DoB = sanitizeInput(request.form["dob"])
        
        isValid, message = dbHandler.validatePassword(password)
        if not isValid:
            error = message
            return render_template("/signup.html", error=error)
            
        totp_secret = dbHandler.insertUser(username, password, DoB, email)
        if totp_secret:
            qr_code = dbHandler.generateQRCode(username, totp_secret)
            return render_template("/setup_2fa.html", qr_code=qr_code, secret=totp_secret, username=username)
        else:
            error = "An error occurred during account creation"
            return render_template("/signup.html", error=error)
    else:
        return render_template("/signup.html", error=error)

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

@app.route("/index.html", methods=["POST", "GET"])
@app.route("/", methods=["POST", "GET"])
@limiter.limit("10 per minute")
def home():
    error = None
    if request.method == "GET" and request.args.get("url"):
        url = request.args.get("url", "")
        if isValidRedirect(url):
            return redirect(url, code=302)
        else:
            return redirect("/", code=302)
    if request.method == "POST":
        username = sanitizeInput(request.form["username"])
        password = request.form["password"]
        
        isPasswordValid, user = dbHandler.retrieveUsers(username, password)
        
        if isPasswordValid:
            session['temp_username'] = username
            return render_template("/verify_2fa.html", username=username)
        else:
            error = "Invalid username or password"
            return render_template("/index.html", error=error)
    else:
        message = request.args.get('message', '')
        return render_template("/index.html", message=message, error=error)

@app.route("/verify_login_2fa", methods=["POST"])
@limiter.limit("5 per minute")
def verify_login_2fa():
    if request.method == "POST":
        username = request.form["username"]
        token = request.form["token"]
        
        if 'temp_username' not in session or session['temp_username'] != username:
            return redirect("/")
        
        secret = dbHandler.getTOTPSecret(username)
        if not secret:
            return render_template("/verify_2fa.html", error="Invalid credentials", username=username)
        
        if dbHandler.verifyTOTP(secret, token):
            session.pop('temp_username', None)
            session['user'] = username
            dbHandler.listFeedback()
            return render_template("/success.html", value=username, state=True)
        else:
            return render_template("/verify_2fa.html", 
                               error="Invalid code. Please try again.", 
                               username=username)

@app.route("/logout")
def logout():
    session.pop('user', None)
    session.pop('temp_username', None)
    return redirect("/?message=You have been logged out successfully.")

@app.after_request
def setSecurityHeaders(response):
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

if __name__ == "__main__":
    app.config["TEMPLATES_AUTO_RELOAD"] = True
    app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0
    app.config["SESSION_COOKIE_SECURE"] = True
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = 'Lax'
    app.run(debug=True, host="0.0.0.0", port=8080)
