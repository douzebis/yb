from __future__ import annotations
from datetime import datetime

def format_timestamp(ts: int) -> str:
    dt = datetime.fromtimestamp(ts)  # convert to local datetime
    return dt.strftime('%c')  # locale-appropriate datetime string


class StringTooLargeError(ValueError):
    pass