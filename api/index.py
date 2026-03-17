import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app

# Export the Flask app as the handler for Vercel
# The WSGI app is exposed as a module-level variable named `app`
