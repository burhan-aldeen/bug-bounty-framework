import atexit
import logging
import sys
from logging.handlers import QueueHandler, QueueListener, RotatingFileHandler
from pathlib import Path
from queue import Queue

_LOGGER_INITIALIZED: bool = False
_listener: QueueListener | None = None


def configure_logging(log_file: Path | str = "scan.log", level: str = "INFO") -> None:
    global _LOGGER_INITIALIZED, _listener
    if _LOGGER_INITIALIZED:
        return

    log_path = Path(log_file)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    root.handlers.clear()

    queue: Queue = Queue(10000)
    queue_handler = QueueHandler(queue)
    queue_handler.setLevel(logging.DEBUG)
    root.addHandler(queue_handler)

    formatter = logging.Formatter("%(asctime)s | %(levelname)-8s | %(message)s")

    stream_handler = logging.StreamHandler(sys.stderr)
    stream_handler.setFormatter(formatter)
    stream_handler.setLevel(getattr(logging, level.upper(), logging.INFO))

    file_handler = RotatingFileHandler(
        str(log_path), maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8"
    )
    file_handler.setFormatter(formatter)
    file_handler.setLevel(logging.DEBUG)

    _listener = QueueListener(queue, stream_handler, file_handler)
    _listener.start()
    atexit.register(_stop_listener)

    _LOGGER_INITIALIZED = True


def _stop_listener() -> None:
    if _listener is not None:
        _listener.stop()


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
