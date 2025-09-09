import logging
import os

os.makedirs("logs", exist_ok=True)

logger = logging.getLogger("SuspiciousLogger")
logger.setLevel(logging.INFO)

handler = logging.FileHandler("logs/suspicious.log")
formatter = logging.Formatter("%(asctime)s - %(message)s")
handler.setFormatter(formatter)

logger.addHandler(handler)
