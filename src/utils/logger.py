import logging
import os
from logging.handlers import RotatingFileHandler

os.makedirs("docs/logs", exist_ok=True)

# Set up the rotating log file handler
_file_handler = RotatingFileHandler("docs/logs/app.log", maxBytes=10**6, backupCount=5, encoding="utf-8")
_file_handler.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s %(name)s: %(message)s", datefmt="%Y-%m-%d %H:%M:%S"))

logging.basicConfig(level=logging.INFO)
root_logger = logging.getLogger()
root_logger.handlers.clear() # Remove the default handlers
root_logger.addHandler(_file_handler)

def get_logger(module_name: str) -> logging.Logger:
    """
    Returns a configured logger instance for the given module.
    """
    return logging.getLogger(module_name)


if __name__ == "__main__":
    _log = get_logger(__name__)
    _log.info("[OK] System Initialized.")
