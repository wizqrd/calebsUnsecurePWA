document.addEventListener('DOMContentLoaded', function() {
    // Get input elements
    const usernameInput = document.getElementById('username-input');
    const emailInput = document.getElementById('email-input');
    const passwordInput = document.getElementById('password-input');
    
    // Get username validation elements
    if (usernameInput) {
        const usernameLengthReq = document.getElementById('username-length');
        const usernameAlphanumericReq = document.getElementById('username-alphanumeric');
        
        // Regular expressions for username validation
        const usernameLengthRegex = /^.{3,}$/;
        const usernameAlphanumericRegex = /^[a-zA-Z0-9_]+$/;
        
        // Add event listener for username input changes
        usernameInput.addEventListener('input', function() {
            const username = usernameInput.value;
            
            // Validate username requirements
            updateValidation(usernameLengthReq, usernameLengthRegex.test(username));
            updateValidation(usernameAlphanumericReq, usernameAlphanumericRegex.test(username));
        });
    }
    
    // Get email validation elements
    if (emailInput) {
        const emailFormatReq = document.getElementById('email-format');
        
        // Regular expression for email validation
        const emailFormatRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
        
        // Add event listener for email input changes
        emailInput.addEventListener('input', function() {
            const email = emailInput.value;
            
            // Validate email requirements
            updateValidation(emailFormatReq, emailFormatRegex.test(email));
        });
    }
    
    // Get password validation elements
    if (passwordInput) {
        const lengthReq = document.getElementById('length-req');
        const uppercaseReq = document.getElementById('uppercase-req');
        const lowercaseReq = document.getElementById('lowercase-req');
        const numberReq = document.getElementById('number-req');
        const specialReq = document.getElementById('special-req');
        
        // Regular expressions for password validation
        const lengthRegex = /^.{8,20}$/;
        const uppercaseRegex = /[A-Z]/;
        const lowercaseRegex = /[a-z]/;
        const numberRegex = /[0-9]/;
        const specialRegex = /[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]/;
        
        // Add event listener for password input changes
        passwordInput.addEventListener('input', function() {
            const password = passwordInput.value;
            
            // Validate password requirements
            updateValidation(lengthReq, lengthRegex.test(password));
            updateValidation(uppercaseReq, uppercaseRegex.test(password));
            updateValidation(lowercaseReq, lowercaseRegex.test(password));
            updateValidation(numberReq, numberRegex.test(password));
            updateValidation(specialReq, specialRegex.test(password));
        });
    }
    
    // Function to update the validation UI
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