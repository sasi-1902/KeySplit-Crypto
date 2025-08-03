# logging_utils.py

import logging
import os

def setup_logging(log_file="transactions.log"):
    log_path = os.path.abspath(log_file)
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s", "%Y-%m-%d %H:%M:%S")

    if not logger.handlers:
        file_handler = logging.FileHandler(log_path)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

def log_transaction(user_id, action, status):
    logging.info(f"User:{user_id} - Action:{action} - Status:{status}")
