import logging
from logging.handlers import RotatingFileHandler

from warppocket.storage import AppPaths, private_file


def create_logger(paths: AppPaths):
    logger = logging.getLogger(f"warppocket.{paths.root}")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    if not logger.handlers:
        path = paths.logs / "diagnostics.log"
        handler = RotatingFileHandler(path, maxBytes=262144, backupCount=2, encoding="utf-8")
        private_file(path)
        handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
        logger.addHandler(handler)
    return logger


def event(logger, code: str, *, role=None, endpoint=None, exit_code=None):
    """Only caller-owned event codes and non-secret structured fields are accepted."""
    logger.info("event=%s role=%s endpoint=%s exit_code=%s", code, role or "-", endpoint or "-", exit_code if exit_code is not None else "-")
