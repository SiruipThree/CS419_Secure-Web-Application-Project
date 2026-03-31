import bcrypt
import time
import re
from pathlib import Path
from logging_utils import security_log, access_log
from secure_app.storage import load_json, save_json
from security import validate_password_strength, validate_email, validate_username

class UserAuth:
    def __init__(self, users_file='data/users.json', rate_limits_file='data/rate_limits.json'):
        # Convert string paths to pathlib.Path objects for your storage functions
        self.users_file = Path(users_file)
        self.rate_limits_file = Path(rate_limits_file)

    def _check_rate_limit(self, ip_address):
        """Max 10 login attempts per IP per minute"""
        limits = load_json(self.rate_limits_file, {})
        now = time.time()
        
        # Keep only attempts from the last 60 seconds
        attempts = [t for t in limits.get(ip_address, []) if now - t < 60]
        
        if len(attempts) >= 10:
            return False
        
        attempts.append(now)
        limits[ip_address] = attempts
        
        # Using your exact save_json function
        save_json(self.rate_limits_file, limits)
        return True

    def register(self, username, email, password, confirm_password):
        if password != confirm_password:
            security_log.log_event('VALIDATION_FAILED', user_id=username, details={'reason': 'Passwords do not match'}, severity='WARNING')
            return {"error": "Passwords do not match"}

        is_valid = validate_username(username)
        if not is_valid:
            security_log.log_event('VALIDATION_FAILED', user_id=username, details={'reason': 'Invalid username format'}, severity='WARNING')
            return {"error": "Invalid username format"}
        
        is_valid = validate_email(email)
        if not is_valid:
            security_log.log_event('VALIDATION_FAILED', user_id=username, details={'reason': 'Invalid email format'}, severity='WARNING')
            return {"error": "Invalid email format"}
        
        is_valid, validation_message = validate_password_strength(password)
        if not is_valid:
            security_log.log_event('VALIDATION_FAILED', user_id=username, details={'reason': validation_message}, severity='WARNING')
            return {"error": validation_message}

        users = load_json(self.users_file, {})
        
        if username in users:
            security_log.log_event('REGISTRATION_FAILED', user_id=username, details={'reason': 'Username already taken'}, severity='WARNING')
            return {"error": "Username already taken"}
        if any(u['email'] == email for u in users.values()):
            security_log.log_event('REGISTRATION_FAILED', user_id=username, details={'reason': 'Email already registered'}, severity='WARNING')
            return {"error": "Email already registered"}

        # Hashing with required cost factor 12
        salt = bcrypt.gensalt(rounds=12)
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)

        users[username] = {
            "username": username,
            "email": email,
            "password_hash": hashed.decode('utf-8'),
            "created_at": time.time(),
            "role": "user",
            "failed_attempts": 0,
            "locked_until": None
        }
        
        save_json(self.users_file, users)
        security_log.log_event('USER_REGISTERED', user_id=username, details={'action': 'New user registration'})    
        return {"success": "User registered successfully"}

    def login(self, username, password, ip_address):
        if not self._check_rate_limit(ip_address):
            security_log.log_event(
                'SUSPICIOUS_ACTIVITY', 
                user_id=username, 
                details={'reason': 'Rate limit exceeded - Possible brute force'}, 
                severity='WARNING'
            )
            return {"error": "Rate limit exceeded. Try again in a minute."}

        users = load_json(self.users_file, {})
        user = users.get(username)

        # Generic error to prevent username enumeration
        if not user:
            return {"error": "Invalid credentials"}

        # Check account lockout status
        if user['locked_until'] and time.time() < user['locked_until']:
            remaining = int((user['locked_until'] - time.time()) / 60)
            return {"error": f"Account locked. Try again in {remaining} minutes."}

        # Verify Password
        if bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
            user['failed_attempts'] = 0
            user['locked_until'] = None
            save_json(self.users_file, users)
            security_log.log_event('LOGIN_SUCCESS', user_id=username, details={'action': 'Credentials verified'})
            security_log.log_event('SESSION_CREATED', user_id=username, details={'action': 'Auth token generated'}) 
            return {"success": True, "user_id": username}
        else:
            user['failed_attempts'] += 1
            if user['failed_attempts'] >= 5:
                # Lockout for 15 minutes
                user['locked_until'] = time.time() + (15 * 60)
                security_log.log_event(
                    'ACCOUNT_LOCKED', 
                    user_id=username, 
                    details={'reason': 'Exceeded maximum failed attempts (5)'}, 
                    severity='ERROR'
                )
            
            save_json(self.users_file, users)
            security_log.log_event(
                'LOGIN_FAILED', 
                user_id=username, 
                details={'reason': 'Invalid password match'}, 
                severity='WARNING'
            )
            return {"error": "Invalid credentials"}
        

    def change_password(self, username, old_password, new_password, confirm_password):
        users = load_json(self.users_file, {})
        user = users.get(username)

        # Fail safe if user doesn't exist in the system
        if not user:
            return {"error": "User not found."}

        # 1. Verify the current password
        if not bcrypt.checkpw(old_password.encode('utf-8'), user['password_hash'].encode('utf-8')):
            security_log.log_event(
                'VALIDATION_FAILED', 
                user_id=username, 
                details={'reason': 'Password change failed - Incorrect current password'}, 
                severity='WARNING'
            )
            return {"error": "Incorrect current password."}

        # 2. Confirm the new passwords match
        if new_password != confirm_password:
            return {"error": "New passwords do not match."}

        # 3. Prevent reusing the current password
        if bcrypt.checkpw(new_password.encode('utf-8'), user['password_hash'].encode('utf-8')):
            return {"error": "New password cannot be the same as the current password."}

        # 4. Enforce complexity requirements on the new password using the security module
        is_valid, validation_message = validate_password_strength(new_password)
        if not is_valid:
            security_log.log_event(
                'VALIDATION_FAILED', 
                user_id=username, 
                details={'reason': f'Password change failed - {validation_message}'}, 
                severity='WARNING'
            )
            return {"error": validation_message}

        # 5. Hash the new password with cost factor 12
        salt = bcrypt.gensalt(rounds=12)
        hashed = bcrypt.hashpw(new_password.encode('utf-8'), salt)

        # 6. Update the user dictionary and save to JSON
        user['password_hash'] = hashed.decode('utf-8')
        save_json(self.users_file, users)

        # 7. Log the successful system change
        security_log.log_event(
            'PASSWORD_CHANGE', 
            user_id=username, 
            details={'action': 'User successfully updated their password'}
        )
        
        return {"success": "Password updated successfully."}