import os
import sys

# Add project root to Python path
project_root = os.path.dirname(os.path.abspath(__file__))
if project_root not in sys.path:
    sys.path.append(project_root)

try:
    from fire.app import app
except Exception as e:
    print(f"Error importing app: {str(e)}")
    sys.exit(1)

if __name__ == "__main__":
    try:
        # Always use port 10000
        port = int(os.environ.get("PORT", 10000))
        app.run(host='0.0.0.0', port=port)
    except Exception as e:
        print(f"Error starting server: {str(e)}")
        sys.exit(1)
