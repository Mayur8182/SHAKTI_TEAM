import pytesseract
from PIL import Image
import re
import csv
import os

def preprocess_image(img):
    """Preprocess image to improve OCR accuracy"""
    # Convert to grayscale
    img = img.convert('L')
    # Increase contrast
    img = img.point(lambda x: 0 if x < 128 else 255, '1')
    return img

def clean_aadhaar_number(text):
    """Clean and extract Aadhaar number from text"""
    print(f"[DEBUG] Raw text for cleaning:\n{text}")
    
    # First clean up the text
    # Remove any lines with VID
    lines = text.split('\n')
    filtered_lines = []
    for line in lines:
        if 'VID' not in line.upper():
            # Remove common OCR mistakes
            line = line.replace('l', '1').replace('I', '1').replace('O', '0').replace('o', '0')
            filtered_lines.append(line)
    
    text = '\n'.join(filtered_lines)
    print(f"[DEBUG] Text after filtering VID lines:\n{text}")
    
    # Look for numbers in exact 4-4-4 format with proper spacing
    # This pattern requires exactly one space between groups and no digits before/after
    strict_pattern = r'(?<!\d)(\d{4})\s(\d{4})\s(\d{4})(?!\d)'
    strict_matches = re.finditer(strict_pattern, text)
    
    for match in strict_matches:
        # Get the full matched text for debugging
        full_match = match.group(0)
        print(f"[DEBUG] Found potential match: {full_match}")
        
        # Combine the digit groups
        aadhaar = ''.join([match.group(1), match.group(2), match.group(3)])
        if len(aadhaar) == 12:
            print(f"[DEBUG] Extracted valid Aadhaar: {aadhaar}")
            return aadhaar
    
    # If no strict matches found, try with more lenient spacing
    lenient_pattern = r'(?<!\d)(\d{4})\s*(\d{4})\s*(\d{4})(?!\d)'
    lenient_matches = re.finditer(lenient_pattern, text)
    
    for match in lenient_matches:
        full_match = match.group(0)
        print(f"[DEBUG] Found lenient match: {full_match}")
        
        aadhaar = ''.join([match.group(1), match.group(2), match.group(3)])
        if len(aadhaar) == 12:
            print(f"[DEBUG] Extracted valid Aadhaar (lenient): {aadhaar}")
            return aadhaar
    
    # As a last resort, look for any 12 consecutive digits
    # But only if they're on a line by themselves
    for line in filtered_lines:
        # Remove all non-digits
        clean_line = re.sub(r'[^0-9]', '', line)
        if len(clean_line) == 12:
            print(f"[DEBUG] Found 12-digit number on line: {line.strip()}")
            print(f"[DEBUG] Cleaned number: {clean_line}")
            return clean_line
    
    print("[DEBUG] No valid Aadhaar number pattern found")
    return None

# Function to extract Aadhaar number from an image
def extract_aadhaar(image_path):
    try:
        print(f"\n[DEBUG] Processing image: {image_path}")
        if not os.path.exists(image_path):
            print("[ERROR] Image file does not exist")
            return None
            
        # Open and preprocess image
        img = Image.open(image_path)
        img = preprocess_image(img)
        
        # Extract text using different OCR configurations
        text = pytesseract.image_to_string(img)
        print(f"[DEBUG] Extracted raw text:\n{text}")
        
        # Clean and find Aadhaar number
        aadhaar = clean_aadhaar_number(text)
        print(f"[DEBUG] Cleaned Aadhaar number: {aadhaar}")
        
        return aadhaar
    except Exception as e:
        print(f"[ERROR] Error extracting Aadhaar: {str(e)}")
        return None

# Function to check if an Aadhaar number exists in the CSV
def find_user_by_aadhaar(aadhaar_number, file_path="dataset.csv"):
    try:
        print(f"\n[DEBUG] Searching for Aadhaar: {aadhaar_number}")
        if not aadhaar_number:
            print("[ERROR] Invalid Aadhaar number")
            return None, None
            
        # Get absolute path for dataset.csv if it's in the same directory
        if not os.path.isabs(file_path):
            current_dir = os.path.dirname(os.path.abspath(__file__))
            file_path = os.path.join(current_dir, file_path)
            
        if not os.path.exists(file_path):
            print(f"[ERROR] Dataset file not found at {file_path}")
            return None, None
            
        # Clean the input Aadhaar number
        aadhaar_number = re.sub(r'[^0-9]', '', str(aadhaar_number))
        if len(aadhaar_number) > 0:
            aadhaar_number = aadhaar_number.zfill(12)
        print(f"[DEBUG] Cleaned input Aadhaar: {aadhaar_number}")
        
        try:
            with open(file_path, mode="r", encoding='utf-8-sig') as file:
                reader = csv.DictReader(file)
                print("[DEBUG] Successfully opened dataset.csv")
                
                # Convert the reader to a list to check if it's empty
                rows = list(reader)
                if not rows:
                    print("[ERROR] Dataset is empty")
                    return None, None
                    
                for row in rows:
                    if not row.get("aadhaar_no"):
                        print("[WARNING] Row missing aadhaar_no")
                        continue
                        
                    # Clean the Aadhaar number in the dataset for comparison
                    db_aadhaar = re.sub(r'[^0-9]', '', str(row["aadhaar_no"]))
                    if len(db_aadhaar) > 0:
                        db_aadhaar = db_aadhaar.zfill(12)
                    print(f"[DEBUG] Comparing with DB Aadhaar: {db_aadhaar}")
                    
                    if db_aadhaar == aadhaar_number:
                        name = row.get("name", "").strip()
                        phone = row.get("phone_no", "")
                        if phone and phone.upper() == "NULL":
                            phone = None
                        print(f"[DEBUG] Match found! Name: {name}, Phone: {phone}")
                        return name, phone
                        
        except UnicodeDecodeError:
            print("[ERROR] File encoding issue. Trying with different encoding...")
            with open(file_path, mode="r", encoding='latin-1') as file:
                # Repeat the same process with different encoding
                reader = csv.DictReader(file)
                for row in reader:
                    db_aadhaar = re.sub(r'[^0-9]', '', str(row["aadhaar_no"]))
                    if len(db_aadhaar) > 0:
                        db_aadhaar = db_aadhaar.zfill(12)
                    if db_aadhaar == aadhaar_number:
                        name = row.get("name", "").strip()
                        phone = row.get("phone_no", "")
                        if phone and phone.upper() == "NULL":
                            phone = None
                        return name, phone
                        
        print("[DEBUG] No matching Aadhaar number found in dataset")
        return None, None
    except Exception as e:
        print(f"[ERROR] Error searching dataset: {str(e)}")
        import traceback
        print(f"[ERROR] Traceback: {traceback.format_exc()}")
        return None, None
