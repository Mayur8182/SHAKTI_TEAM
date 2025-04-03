import pytesseract
from PIL import Image
import re
import os

def extract_aadhaar(image_path):
    try:
        # Set tesseract path from environment variable
        tesseract_path = os.getenv('TESSERACT_PATH', '/usr/bin/tesseract')
        pytesseract.pytesseract.tesseract_cmd = tesseract_path
        
        # Verify tesseract is available
        if not os.path.exists(tesseract_path):
            raise Exception(f"Tesseract not found at {tesseract_path}")
        
        img = Image.open(image_path)
        text = pytesseract.image_to_string(img)
        aadhaar_pattern = r'\d{4}\s\d{4}\s\d{4}'
        match = re.search(aadhaar_pattern, text)
        return match.group(0) if match else None
    except Exception as e:
        print(f"Error extracting Aadhaar: {str(e)}")
        return None

def find_user_by_aadhaar(aadhaar_number):
    # Mock implementation - replace with actual database lookup
    return "Test User", "1234567890"
