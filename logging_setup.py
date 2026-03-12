from __future__ import annotations

import logging
import os
from logging.handlers import RotatingFileHandler

from config import AppConfig


def setup_logging(config: AppConfig) -> logging.Logger:
    os.makedirs(config.log_dir, exist_ok=True)

    # подавляем шум сторонних библиотек
    logging.getLogger("paramiko.transport").setLevel(logging.CRITICAL)
    logging.getLogger("paramiko").setLevel(logging.CRITICAL)

    level = getattr(logging, config.log_level.upper(), logging.INFO)

    logger = logging.getLogger("mikrotik_audit")

    # если уже инициализирован — не дублируем handlers
    if logger.handlers:
        return logger

    logger.setLevel(level)

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)-7s | %(threadName)s | %(message)s",
        "%Y-%m-%d %H:%M:%S",
    )

    # основной лог
    file_handler = RotatingFileHandler(
        os.path.join(config.log_dir, config.log_file),
        maxBytes=10 * 1024 * 1024,
        backupCount=5,
        encoding="utf-8",
    )
    file_handler.setLevel(level)
    file_handler.setFormatter(formatter)

    # лог ошибок
    error_handler = RotatingFileHandler(
        os.path.join(config.log_dir, config.error_log_file),
        maxBytes=5 * 1024 * 1024,
        backupCount=3,
        encoding="utf-8",
    )
    error_handler.setLevel(logging.ERROR)
    error_handler.setFormatter(formatter)

    # консоль
    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    logger.addHandler(error_handler)
    logger.addHandler(console_handler)

    logger.propagate = False

    return logger