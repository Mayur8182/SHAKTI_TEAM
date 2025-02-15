from aadhaar_utils import extract_aadhaar, find_user_by_aadhaar
import os

def test_aadhaar_verification(image_path):
    print("Testing Aadhaar verification...")
    print(f"Image path: {image_path}")
    
    # Check if file exists
    if not os.path.exists(image_path):
        print(f"Error: File not found at {image_path}")
        return
    
    # Try to extract Aadhaar number
    print("\nExtracting Aadhaar number...")
    extracted_aadhaar = extract_aadhaar(image_path)
    print(f"Extracted Aadhaar number: {extracted_aadhaar}")
    
    if extracted_aadhaar:
        # Try to find user in dataset
        print("\nLooking up in dataset...")
        name, phone = find_user_by_aadhaar(extracted_aadhaar)
        print(f"Database lookup result - Name: {name}, Phone: {phone}")
    else:
        print("Failed to extract Aadhaar number from image")

if __name__ == "__main__":
    # Get the image path from user
    image_path = input("Enter the path to your Aadhaar card image: ")
    test_aadhaar_verification(image_path)
