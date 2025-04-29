/**
 * Real-Time Form Validation Script
 * 
 * This script provides immediate feedback to users as they type in form fields.
 * It validates input in real-time without requiring form submission,
 * improving both user experience and security.
 * 
 * Security benefits:
 * - Guides users to create secure passwords that meet complexity requirements
 * - Validates email format to ensure proper communication
 * - Ensures username follows required patterns to prevent injection attacks
 * - Provides instant visual feedback rather than waiting for server validation
 */

// Wait until the document is fully loaded before running the script
document.addEventListener('DOMContentLoaded', function() {
    // Get references to the input fields from the DOM
    const usernameInput = document.getElementById('username-input');
    const emailInput = document.getElementById('email-input');
    const passwordInput = document.getElementById('password-input');
    
    // ===============================
    // Username Validation
    // ===============================
    
    if (usernameInput) {
        // Get references to the validation message elements for username
        const usernameLengthReq = document.getElementById('username-length');
        const usernameAlphanumericReq = document.getElementById('username-alphanumeric');
        
        // Define the validation rules using regular expressions
        // These ensure the username meets our security requirements
        const usernameLengthRegex = /^.{3,20}$/;         // Between 3 and 20 characters
        const usernameAlphanumericRegex = /^[a-zA-Z0-9_]+$/;  // Only letters, numbers, and underscores
        
        // Set up real-time validation as the user types
        usernameInput.addEventListener('input', function() {
            const username = usernameInput.value;
            
            // Check each validation rule and update the UI accordingly
            updateValidation(usernameLengthReq, usernameLengthRegex.test(username));
            updateValidation(usernameAlphanumericReq, usernameAlphanumericRegex.test(username));
        });
    }
    
    // ===============================
    // Email Validation
    // ===============================
    
    if (emailInput) {
        // Get reference to the email validation message element
        const emailFormatReq = document.getElementById('email-format');
        
        // Define the validation rule for email format
        // This is a simplified version but covers most common email formats
        const emailFormatRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
        
        // Set up real-time validation as the user types
        emailInput.addEventListener('input', function() {
            const email = emailInput.value;
            
            // Check email format and update the UI
            updateValidation(emailFormatReq, emailFormatRegex.test(email));
        });
    }
    
    // ===============================
    // Password Validation
    // ===============================
    
    if (passwordInput) {
        // Get references to all the password requirement elements
        const lengthReq = document.getElementById('length-req');
        const uppercaseReq = document.getElementById('uppercase-req');
        const lowercaseReq = document.getElementById('lowercase-req');
        const numberReq = document.getElementById('number-req');
        const specialReq = document.getElementById('special-req');
        
        // Define the validation rules for password security
        // Each rule is a separate regex to make the code clearer
        const lengthRegex = /^.{8,20}$/;                          // Between 8 and 20 characters
        const uppercaseRegex = /[A-Z]/;                           // At least one uppercase letter
        const lowercaseRegex = /[a-z]/;                           // At least one lowercase letter
        const numberRegex = /[0-9]/;                              // At least one number
        const specialRegex = /[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]/;  // At least one special character
        
        // Set up real-time validation as the user types their password
        passwordInput.addEventListener('input', function() {
            const password = passwordInput.value;
            
            // Check each password requirement and update the UI for each one
            updateValidation(lengthReq, lengthRegex.test(password));
            updateValidation(uppercaseReq, uppercaseRegex.test(password));
            updateValidation(lowercaseReq, lowercaseRegex.test(password));
            updateValidation(numberReq, numberRegex.test(password));
            updateValidation(specialReq, specialRegex.test(password));
        });
    }
    
    // ===============================
    // Helper Functions
    // ===============================
    
    /**
     * Updates the validation UI for a requirement based on whether it passes or fails
     * 
     * @param {HTMLElement} element - The element to update
     * @param {boolean} isValid - Whether the validation passed
     */
    function updateValidation(element, isValid) {
        // Skip if the element doesn't exist
        if (!element) return;
        
        if (isValid) {
            // For valid input:
            // 1. Remove any 'invalid' styling
            // 2. Add 'valid' styling
            // 3. Add a checkmark (✓) to show it's valid
            element.classList.remove('invalid');
            element.classList.add('valid');
            element.innerHTML = '✓ ' + element.textContent.replace('✓ ', '').replace('✗ ', '');
        } else {
            // For invalid input:
            // 1. Remove any 'valid' styling
            // 2. Add 'invalid' styling
            // 3. Add an X mark (✗) to show it's invalid
            element.classList.remove('valid');
            element.classList.add('invalid');
            element.innerHTML = '✗ ' + element.textContent.replace('✓ ', '').replace('✗ ', '');
        }
    }
}); 