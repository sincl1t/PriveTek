"""Sanitize log output, including third-party HTTP request messages."""
import logging
import re


class PrivacyFilter(logging.Filter):
    def filter(self, record):
        message = record.getMessage()
        message = re.sub(r'https?://[^\s\"\']+', '[URL redacted]', message)
        message = re.sub(r'[\w.+%-]+(?:@|%40)[\w.-]+', '[email redacted]', message,
                         flags=re.IGNORECASE)
        record.msg, record.args = message, ()
        # Exception text can contain request bodies, credentials or personal data.
        if record.exc_info:
            record.msg += ' exception=' + record.exc_info[0].__name__
            record.exc_info = None
        record.exc_text = None
        record.stack_info = None
        return True


def configure_logging():
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s %(levelname)s %(message)s')
    for name in ('', 'uvicorn', 'uvicorn.error', 'uvicorn.access', 'httpx', 'httpcore'):
        logger = logging.getLogger(name)
        for handler in logger.handlers:
            if not any(isinstance(item, PrivacyFilter) for item in handler.filters):
                handler.addFilter(PrivacyFilter())
    for name in ('httpx', 'httpcore'):
        logging.getLogger(name).setLevel(logging.WARNING)
