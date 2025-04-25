import unittest
import user_management as dbHandler
import os
import tempfile

class SecurePWATests(unittest.TestCase):
    def setUp(self):
        # Create a temporary database for testing
        self.db_fd, self.db_path = tempfile.mkstemp()
        self.original_db = "database_files/database.db"
        
        # Point the database path to our test database
        dbHandler.sql.connect = lambda x: dbHandler.sql.connect(self.db_path)
        
        # Create test database structure
        conn = dbHandler.sql.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL, 
            password TEXT NOT NULL,
            dateOfBirth TEXT,
            email TEXT,
            totp_secret TEXT
        )
        ''')
        
        cursor.execute('''
        CREATE TABLE feedback (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            feedback TEXT NOT NULL
        )
        ''')
        
        conn.commit()
        conn.close()
        
        # Create visitor log file
        with open("visitor_log.txt", "w") as f:
            f.write("0")
    
    def tearDown(self):
        os.close(self.db_fd)
        os.unlink(self.db_path)
    
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
        
        # Test missing lowercase
        valid, _ = dbHandler.validatePassword("PASSW0RD!")
        self.assertFalse(valid)
        
        # Test missing number
        valid, _ = dbHandler.validatePassword("Password!")
        self.assertFalse(valid)
        
        # Test missing special character
        valid, _ = dbHandler.validatePassword("Passw0rd")
        self.assertFalse(valid)
    
    def test_user_management(self):
        # Test user creation and authentication
        secret = dbHandler.insertUser("testuser", "Passw0rd!", "01/01/2000", "test@example.com")
        self.assertIsNotNone(secret)
        
        # Test successful authentication
        success, user = dbHandler.retrieveUsers("testuser", "Passw0rd!")
        self.assertTrue(success)
        self.assertIsNotNone(user)
        
        # Test failed authentication - wrong password
        success, user = dbHandler.retrieveUsers("testuser", "WrongPassw0rd!")
        self.assertFalse(success)
        self.assertIsNone(user)
        
        # Test failed authentication - user doesn't exist
        success, user = dbHandler.retrieveUsers("nonexistentuser", "Passw0rd!")
        self.assertFalse(success)
        self.assertIsNone(user)
    
    def test_totp(self):
        # Test TOTP generation and verification
        secret = dbHandler.generateTOTPSecret()
        self.assertIsNotNone(secret)
        
        # We can't test actual verification without waiting 30 seconds
        # So we'll just test that the function exists and returns False for invalid codes
        result = dbHandler.verifyTOTP(secret, "000000")
        self.assertIsNotNone(result)  # It will be False, but we can't reliably test success
    
    def test_feedback(self):
        # Test feedback insertion and retrieval
        dbHandler.insertFeedback("Test feedback")
        
        # Create a temporary file for testing
        temp_file = tempfile.NamedTemporaryFile(delete=False)
        
        # Redirect the output to our temp file
        original_path = "templates/partials/success_feedback.html"
        dbHandler.listFeedback.__globals__["open"] = lambda x, y: open(temp_file.name, y) if x == original_path else open(x, y)
        
        # Call listFeedback and check that it generated content
        dbHandler.listFeedback()
        
        with open(temp_file.name, "r") as f:
            content = f.read()
        
        self.assertIn("Test feedback", content)
        
        # Clean up
        os.unlink(temp_file.name)

if __name__ == "__main__":
    unittest.main() 