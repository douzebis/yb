# SPDX-FileCopyrightText: 2025 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
#
# SPDX-License-Identifier: MIT

from __future__ import annotations
from datetime import datetime

def format_timestamp(ts: int) -> str:
    dt = datetime.fromtimestamp(ts)  # convert to local datetime
    return dt.strftime('%c')  # locale-appropriate datetime string


class StringTooLargeError(ValueError):
    pass
