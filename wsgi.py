import os
import sys
import eventlet
import logging

eventlet.monkey_patch()

try:
    from fire.app import app
except Exception as e:
    logging.error(f"Failed to import app: {str(e)}")
    sys.exit(1)

if __name__ == "__main__":
    try:
        port = int(os.environ.get("PORT", 8000))
        app.run(host='0.0.0.0', port=port)
    except Exception as e:
        logging.error(f"Failed to start server: {str(e)}")
        sys.exit(1)
