"""Configuration management for the security auditor."""
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()


class Config:
    """Application configuration."""
    
    # AWS Configuration
    AWS_ACCESS_KEY_ID = os.getenv('AWS_ACCESS_KEY_ID')
    AWS_SECRET_ACCESS_KEY = os.getenv('AWS_SECRET_ACCESS_KEY')
    AWS_DEFAULT_REGION = os.getenv('AWS_DEFAULT_REGION', 'us-east-1')
    
    # Database Configuration
    DATABASE_PATH = os.path.join('database', 'results.db')
    
    # Alert Configuration
    ALERT_EMAIL = os.getenv('ALERT_EMAIL')
    SMTP_SERVER = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
    SMTP_PORT = int(os.getenv('SMTP_PORT', '587'))
    SMTP_USERNAME = os.getenv('SMTP_USERNAME')
    SMTP_PASSWORD = os.getenv('SMTP_PASSWORD')
    
    # Scan Configuration
    UNUSED_KEY_DAYS = int(os.getenv('UNUSED_KEY_DAYS', '90'))
    RISK_SCORE_THRESHOLD = int(os.getenv('RISK_SCORE_THRESHOLD', '7'))
    
    # Logging Configuration
    LOG_DIR = 'logs'
    LOG_FILE = os.path.join(LOG_DIR, 'security_alerts.log')
    
    @staticmethod
    def validate():
        """Validate required configuration."""
        required = ['AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY']
        missing = [key for key in required if not getattr(Config, key)]
        
        if missing:
            raise ValueError(f"Missing required configuration: {', '.join(missing)}")
        
        return True


config = Config()

