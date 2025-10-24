import logging


# -----------------
# Configure logging
# -----------------

logging.basicConfig(
    level=logging.INFO,
    format=' %(message)s',
    handlers=[
        logging.FileHandler('wow_server.log'),
        logging.StreamHandler()
    ]
)


# -------------
# Debug Logging
# -------------

# Set debug to true during development
debug = True

def debug_logging(text):
    if debug:
        logging.info(f" DEBUG: {text}")