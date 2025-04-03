import pytesseract
from PIL import Image
import re
import os
import logging

logger = logging.getLogger(__name__)

def get_tesseract_path():
    """Get Tesseract path based on environment"""
    if os.name == 'nt':  # Windows
        return r'C:\Program Files\Tesseract-OCR\tesseract.exe'
    else:  # Linux/Unix
        # Check common locations
        possible_paths = [
            '/usr/bin/tesseract',
            '/usr/local/bin/tesseract',
            '/opt/local/bin/tesseract'
        ]
        for path in possible_paths:
            if os.path.exists(path):
                return path
    return os.getenv('TESSERACT_PATH', 'tesseract')

def extract_aadhaar(image_path):
    """Extract Aadhaar number from image"""
    try:
        # Configure tesseract path
        tesseract_path = get_tesseract_path()
        pytesseract.pytesseract.tesseract_cmd = tesseract_path
        
        # Validate image file
        if not os.path.exists(image_path):
            raise FileNotFoundError(f"Image file not found: {image_path}")
            
        # Open and process image
        with Image.open(image_path) as img:
            # Convert to RGB if necessary
            if img.mode != 'RGB':
                img = img.convert('RGB')
            
            # Extract text
            text = pytesseract.image_to_string(img)
            
            # Look for Aadhaar pattern
            aadhaar_pattern = r'\d{4}\s\d{4}\s\d{4}'
            match = re.search(aadhaar_pattern, text)
            
            if match:
                return match.group(0)
            else:
                logger.warning("No Aadhaar number pattern found in image")
                return None
                
    except Exception as e:
        logger.error(f"Error extracting Aadhaar: {str(e)}")
        return None

def find_user_by_aadhaar(aadhaar_number):
    """Mock function to find user by Aadhaar number"""
    try:
        # Remove spaces from Aadhaar number
        clean_aadhaar = ''.join(aadhaar_number.split())
        
        # Mock implementation - replace with actual database lookup
        # In production, this should query your user database
        mock_data = {
            "123412341234": ("Test User", "9876543210"),
            "987698769876": ("Demo User", "1234567890")
        }
        
        return mock_data.get(clean_aadhaar, (None, None))
        
    except Exception as e:
        logger.error(f"Error finding user by Aadhaar: {str(e)}")
        return None, None
