from __future__ import annotations

import logging
import os
from logging.handlers import QueueHandler, QueueListener, RotatingFileHandler
from queue import SimpleQueue

from config import AppConfig


def _resolve_level(name: str, default: int) -> int:
    return getattr(logging, str(name).upper().strip(), default)


def _close_handler(handler: logging.Handler) -> None:
    try:
        handler.flush()
    except Exception:
        pass
    try:
        handler.close()
    except Exception:
        pass


def shutdown_logging(logger: logging.Logger | None) -> None:
    if logger is None:
        return

    listener = getattr(logger, "_queue_listener", None)
    if listener is not None:
        try:
            listener.stop()
        except Exception:
            pass
        finally:
            setattr(logger, "_queue_listener", None)

    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        _close_handler(handler)


def setup_logging(config: AppConfig) -> logging.Logger:
    os.makedirs(config.log_dir, exist_ok=True)

    for logger_name in (
        "paramiko.transport",
        "paramiko.auth_handler",
        "paramiko.sftp",
        "urllib3",
        "httpx",
    ):
        logging.getLogger(logger_name).setLevel(logging.CRITICAL)

    logging.getLogger("paramiko").setLevel(logging.ERROR)

    file_level = _resolve_level(config.log_file_level, logging.INFO)
    console_level = _resolve_level(config.log_console_level, logging.INFO)
    error_level = logging.ERROR
    logger_level = min(file_level, console_level, error_level)

    logger = logging.getLogger("mikrotik_audit")
    shutdown_logging(logger)
    logger.setLevel(logger_level)

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)-7s | %(threadName)s | %(message)s",
        "%Y-%m-%d %H:%M:%S",
    )

    file_handler = RotatingFileHandler(
        os.path.join(config.log_dir, config.log_file),
        maxBytes=max(config.log_max_bytes_mb, 1) * 1024 * 1024,
        backupCount=max(config.log_backup_count, 1),
        encoding="utf-8",
        delay=True,
    )
    file_handler.setLevel(file_level)
    file_handler.setFormatter(formatter)

    error_handler = RotatingFileHandler(
        os.path.join(config.log_dir, config.error_log_file),
        maxBytes=max(max(config.log_max_bytes_mb // 2, 1), 1) * 1024 * 1024,
        backupCount=max(min(config.log_backup_count, 3), 1),
        encoding="utf-8",
        delay=True,
    )
    error_handler.setLevel(error_level)
    error_handler.setFormatter(formatter)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(console_level)
    console_handler.setFormatter(formatter)

    queue: SimpleQueue[logging.LogRecord] = SimpleQueue()
    queue_handler = QueueHandler(queue)
    queue_handler.setLevel(logger_level)

    listener = QueueListener(
        queue,
        file_handler,
        error_handler,
        console_handler,
        respect_handler_level=True,
    )
    listener.start()

    logger.addHandler(queue_handler)
    setattr(logger, "_queue_listener", listener)

    logger.propagate = False

    return logger
