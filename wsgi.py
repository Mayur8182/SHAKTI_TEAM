import os
import sys

# Add project root to Python path
project_root = os.path.dirname(os.path.abspath(__file__))
if project_root not in sys.path:
    sys.path.append(project_root)

try:
    # Import the Flask app from the correct location
    from fire.app import app
    
    # Create required directories if they don't exist
    os.makedirs(os.path.join(project_root, 'fire', 'static'), exist_ok=True)
    os.makedirs(os.path.join(project_root, 'fire', 'templates'), exist_ok=True)
    
except Exception as e:
    print(f"Error importing app: {str(e)}")
    sys.exit(1)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    app.run(host='0.0.0.0', port=port)
