import logging
import json
from datetime import datetime, timezone
from flask import request, has_request_context

class SecurityLogger:
    def __init__(self, log_file='security_log'):
        self.logger = logging.getLogger('security')
        self.logger.setLevel(logging.INFO)
        
        # Ensure we don't add multiple handlers if instantiated more than once
        if not self.logger.handlers:
            handler = logging.FileHandler(log_file)
            formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)

    def log_event(self, event_type, user_id, details, severity='INFO'):
        """Log security event (Logins, Lockouts, Password Changes)"""
        
        # Safely pull Flask request data only if an active web request is happening
        ip_address = request.remote_addr if has_request_context() else None
        user_agent = request.headers.get('User-Agent') if has_request_context() else None

        log_entry = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'event_type': event_type,
            'user_id': user_id,
            'ip_address': ip_address,
            'user_agent': user_agent,
            'details': details,
            'severity': severity
        }
        
        payload = json.dumps(log_entry)
        
        if severity == 'CRITICAL':
            self.logger.critical(payload)
        elif severity == 'ERROR':
            self.logger.error(payload)
        elif severity == 'WARNING':
            self.logger.warning(payload)
        else:
            self.logger.info(payload)


class AccessLogger:
    def __init__(self, log_file='access_log'):
        self.logger = logging.getLogger('access')
        self.logger.setLevel(logging.INFO)
        
        if not self.logger.handlers:
            handler = logging.FileHandler(log_file)
            formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)

    def log_event(self, event_type, user_id, details, severity='INFO'):
        """Log data access event (Read, Write, Delete Documents)"""
        
        ip_address = request.remote_addr if has_request_context() else None

        log_entry = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'event_type': event_type,
            'user_id': user_id,
            'ip_address': ip_address,
            'details': details,
            'severity': severity
        }
        
        payload = json.dumps(log_entry)
        
        if severity == 'CRITICAL':
            self.logger.critical(payload)
        elif severity == 'ERROR':
            self.logger.error(payload)
        elif severity == 'WARNING':
            self.logger.warning(payload)
        else:
            self.logger.info(payload)

# Instantiate them here so you can easily import them into auth.py and other files
security_log = SecurityLogger()
access_log = AccessLogger()