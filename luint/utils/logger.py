"""
Logger module for LUINT.
Handles logging configuration and provides a consistent logging interface.
"""
import os
import sys
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime

from ..config import DEFAULT_CONFIG

LOG_DIR = os.path.dirname(DEFAULT_CONFIG['logging']['log_file'])

# Logger instance
_logger = None


def setup_logger(log_level=logging.INFO, log_to_file=True, log_dir=LOG_DIR, verbose=False):
    """
    Setup and configure the logger.

    Args:
        log_level (int): Logging level (default: logging.INFO)
        log_to_file (bool): Whether to log to file (default: True)
        log_dir (str): Directory to store log files (default: LOG_DIR)
        verbose (bool): Whether to enable verbose logging (default: False)

    Returns:
        logging.Logger: Configured logger instance
    """
    global _logger

    if _logger is not None:
        return _logger

    # Create logger
    _logger = logging.getLogger('luint')
    _logger.setLevel(logging.DEBUG if verbose else log_level)
    _logger.propagate = False

    # Clear any existing handlers
    if _logger.handlers:
        _logger.handlers.clear()

    # Create formatter
    formatter = logging.Formatter(
        '[%(asctime)s] [%(levelname)s] [%(module)s:%(lineno)d] - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    # Create console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.DEBUG if verbose else log_level)
    console_handler.setFormatter(formatter)
    _logger.addHandler(console_handler)

    # Create file handler if enabled
    if log_to_file:
        try:
            # Create log directory if it doesn't exist
            if not os.path.exists(log_dir):
                os.makedirs(log_dir)

            # Create log filename with current date
            log_filename = os.path.join(
                log_dir,
                f"luint_{datetime.now().strftime('%Y%m%d')}.log"
            )

            # Setup rotating file handler (10 MB max size, keep 5 backup files)
            file_handler = RotatingFileHandler(
                log_filename, 
                maxBytes=10*1024*1024,  # 10 MB
                backupCount=5,
                encoding='utf-8'
            )
            file_handler.setLevel(logging.DEBUG)  # Always log all details to file
            file_handler.setFormatter(formatter)
            _logger.addHandler(file_handler)

        except Exception as e:
            _logger.error(f"Failed to setup file logging: {str(e)}")

    return _logger


def get_logger():
    """
    Get the logger instance. Creates a new one if it doesn't exist.

    Returns:
        logging.Logger: Logger instance
    """
    global _logger
    if _logger is None:
        _logger = setup_logger()
    return _logger


class LoggerAdapter(logging.LoggerAdapter):
    """
    Logger adapter to add context information to log messages.
    """
    def __init__(self, logger, module_name=None, target=None):
        """
        Initialize the logger adapter.

        Args:
            logger (logging.Logger): Logger instance
            module_name (str, optional): Module name for context
            target (str, optional): Target domain/IP for context
        """
        self.module_name = module_name
        self.target = target
        super().__init__(logger, {})

    def process(self, msg, kwargs):
        """
        Process the log message to add context information.

        Args:
            msg (str): Log message
            kwargs (dict): Keyword arguments for the logger

        Returns:
            tuple: (modified_message, modified_kwargs)
        """
        context_parts = []

        if self.module_name:
            context_parts.append(f"module:{self.module_name}")

        if self.target:
            context_parts.append(f"target:{self.target}")

        if context_parts:
            context = " ".join(context_parts)
            msg = f"{msg} ({context})"

        return msg, kwargs