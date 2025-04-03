import multiprocessing
import os

# Server socket - Use PORT from environment variable
bind = f"0.0.0.0:{os.environ.get('PORT', '8000')}"  # Changed default to 8000
backlog = 2048

# Worker configuration
workers = 1  # For free tier
worker_class = 'gthread'  # Changed to gthread
threads = 4
worker_connections = 1000
timeout = 120
keepalive = 5

# Logging
accesslog = '-'
errorlog = '-'
loglevel = 'info'

# Process naming
proc_name = 'fire-noc'

# Server mechanics
daemon = False
pidfile = None
umask = 0
user = None
group = None
tmp_upload_dir = None

# SSL
keyfile = None
certfile = None

# Development
reload = False
reload_engine = 'auto'

# Debug
spew = False
check_config = False

# Server hooks
def on_starting(server):
    pass

def on_reload(server):
    pass

def when_ready(server):
    pass

def on_exit(server):
    pass
