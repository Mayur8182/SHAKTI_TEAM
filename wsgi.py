import os
import sys
import eventlet
import logging
from eventlet import wsgi
import gc
from logging.handlers import RotatingFileHandler
from fire.app import create_app

# Force garbage collection
gc.collect()

# Patch socket operations
eventlet.monkey_patch()

# Configure logging
def setup_logging():
    handler = RotatingFileHandler('app.log', maxBytes=10000000, backupCount=5)
    handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    ))
    handler.setLevel(logging.INFO)
    return handler

try:
    # Create Flask app
    app = create_app(os.getenv('FLASK_ENV', 'development'))
    app.logger.addHandler(setup_logging())
except Exception as e:
    logging.error(f"Failed to create app: {str(e)}")
    sys.exit(1)

if __name__ == "__main__":
    try:
        port = int(os.environ.get("PORT", 8000))
        wsgi.server(
            eventlet.listen(('0.0.0.0', port)), 
            app,
            debug=False,
            log_output=True,
            keepalive=False,
            max_size=10000
        )
    except Exception as e:
        logging.error(f"Failed to start server: {str(e)}")
        sys.exit(1)
