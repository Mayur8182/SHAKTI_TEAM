import os
import sys
import eventlet
import logging
from eventlet import wsgi
import gc

# Force garbage collection
gc.collect()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

try:
    # Patch socket operations
    eventlet.monkey_patch()
    
    # Import the Flask app
    from fire.app import app
    
    # Initialize directories
    upload_dirs = ['uploads', 'static/profile_images', 'static/reports']
    for directory in upload_dirs:
        if not os.path.exists(directory):
            os.makedirs(directory)
            
except Exception as e:
    logging.error(f"Failed to initialize app: {str(e)}")
    sys.exit(1)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    app.run(host='0.0.0.0', port=port)
