"""Pure timezone-aware bounded request parsing for native windows."""
from __future__ import annotations
import re
from dataclasses import dataclass
from datetime import datetime,time,timedelta,timezone
from datetime import timezone as dt_timezone
from zoneinfo import ZoneInfo

class WindowTimeError(ValueError):
    """A controlled, user-safe Codex-first request/result error."""


@dataclass(frozen=True)
class TimeWindow:
    start: datetime
    end: datetime
    requested_text: str

    def __post_init__(self) -> None:
        for value, name in ((self.start, "start"), (self.end, "end")):
            if value.tzinfo is None or value.utcoffset() is None:
                raise WindowTimeError(f"{name} must be timezone-aware")
            if value.utcoffset() != timedelta(0):
                raise WindowTimeError(f"{name} must be UTC")
        if self.end < self.start:
            raise WindowTimeError("time range end must not be before start")
        if not isinstance(self.requested_text, str):
            raise WindowTimeError("requested text must be text")

    @classmethod
    def from_utc(cls, start: datetime, end: datetime, requested_text: str = "") -> "TimeWindow":
        def utc(value: datetime) -> datetime:
            if value.tzinfo is None or value.utcoffset() is None:
                raise WindowTimeError("time bounds must be timezone-aware")
            return value.astimezone(timezone.utc)
        return cls(utc(start), utc(end), requested_text)


def _local_now(now: datetime, tz: ZoneInfo) -> datetime:
    if now.tzinfo is None or now.utcoffset() is None:
        return now.replace(tzinfo=tz)
    return now.astimezone(tz)


def _localize(value: datetime, tz: ZoneInfo) -> datetime:
    candidates = [value.replace(tzinfo=tz, fold=fold).astimezone(timezone.utc) for fold in (0, 1)]
    round_trips = [candidate.astimezone(tz).replace(tzinfo=None) for candidate in candidates]
    if any(round_trip != value for round_trip in round_trips):
        raise WindowTimeError("time range contains a nonexistent local time")
    if candidates[0] != candidates[1]:
        raise WindowTimeError("time range contains an ambiguous local time")
    return candidates[0]


def _parse_wall(text: str, tz: ZoneInfo, *, default_date: datetime) -> datetime:
    text = text.strip()
    formats = (
        "%Y-%m-%d %H:%M",
        "%Y/%m/%d %H:%M",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y/%m/%d %H:%M:%S.%f",
        "%m月%d日 %H:%M",
    )
    for fmt in formats:
        try:
            parsed = datetime.strptime(text, fmt)
        except ValueError:
            continue
        if fmt.startswith("%m月"):
            parsed = parsed.replace(year=default_date.year)
        return _localize(parsed, tz)
    raise WindowTimeError("unsupported or ambiguous time range")


def parse_time_window(request: str, *, now: datetime, timezone: ZoneInfo) -> TimeWindow:
    """Parse the explicitly supported Chinese time forms into UTC bounds."""
    if not isinstance(request, str):
        raise WindowTimeError("request must be text")
    local_now = _local_now(now, timezone)
    text = request.strip()
    if not text:
        raise WindowTimeError("request must not be empty")

    prefix = r"(?:(?:请|麻烦)\s*)?(?:帮我\s*)?(?:(?:看看|看下|查一下|查下|查询)\s*)?"
    suffix = r"\s*(?:，|,)?\s*(?:谁找过我|谁找我|谁联系过我|谁联系我)?\s*[?？。]?"
    recent = re.fullmatch(prefix + r"最近\s*(-?\d+)\s*(分钟|小时|天|周)" + suffix, text)
    if recent:
        quantity = int(recent.group(1))
        if quantity <= 0:
            raise WindowTimeError("time quantity must be a positive integer")
        unit = recent.group(2)
        span = {
            "分钟": timedelta(minutes=quantity),
            "小时": timedelta(hours=quantity),
            "天": timedelta(days=quantity),
            "周": timedelta(weeks=quantity),
        }[unit]
        end = local_now.astimezone(dt_timezone.utc)
        return TimeWindow.from_utc(end - span, end, text)

    if re.fullmatch(prefix + r"今天上午" + suffix, text):
        day = local_now.date()
        start = datetime.combine(day, time(0), timezone)
        end = datetime.combine(day, time(12), timezone)
        return TimeWindow.from_utc(start, end, text)

    if re.fullmatch(prefix + r"今天" + suffix, text):
        start = datetime.combine(local_now.date(), time(0), timezone)
        return TimeWindow.from_utc(start, local_now, text)

    if re.fullmatch(prefix + r"昨天" + suffix, text):
        end = datetime.combine(local_now.date(), time(0), timezone)
        return TimeWindow.from_utc(end - timedelta(days=1), end, text)

    if re.fullmatch(prefix + r"(?:本周|这周)" + suffix, text):
        start_day = local_now.date() - timedelta(days=local_now.weekday())
        start = datetime.combine(start_day, time(0), timezone)
        return TimeWindow.from_utc(start, local_now, text)

    # A fully specified date range denotes complete local calendar days.
    dates = re.fullmatch(prefix + r"(?:从\s*)?(\d{4}-\d{2}-\d{2})\s*到\s*(\d{4}-\d{2}-\d{2})" + suffix, text)
    if dates:
        try:
            start_day = datetime.strptime(dates.group(1), "%Y-%m-%d").date()
            end_day = datetime.strptime(dates.group(2), "%Y-%m-%d").date()
        except ValueError as exc:
            raise WindowTimeError("invalid calendar date") from exc
        return TimeWindow.from_utc(_localize(datetime.combine(start_day, time.min), timezone),
                                   _localize(datetime.combine(end_day, time.max), timezone), text)

    # Absolute local wall-clock range. Date separators and optional spaces are
    # intentionally narrow to avoid silently guessing an ambiguous request.
    absolute = re.fullmatch(
        prefix
        +
        r"从\s*(\d{4}[-/]\d{1,2}[-/]\d{1,2}\s+\d{1,2}:\d{2}(?::\d{2}(?:\.\d{1,6})?)?)\s*到\s*"
        r"(\d{4}[-/]\d{1,2}[-/]\d{1,2}\s+\d{1,2}:\d{2}(?::\d{2}(?:\.\d{1,6})?)?)"
        + suffix,
        text,
    )
    if absolute:
        start = _parse_wall(absolute.group(1), timezone, default_date=local_now)
        end = _parse_wall(absolute.group(2), timezone, default_date=local_now)
        return TimeWindow.from_utc(start, end, text)

    if re.fullmatch(prefix + r"从昨晚\s*十点到现在" + suffix, text):
        yesterday = (local_now - timedelta(days=1)).date()
        start = datetime.combine(yesterday, time(22), timezone)
        return TimeWindow.from_utc(start, local_now, text)

    default_request = (
        r"(?:(?:请|麻烦)\s*)?(?:帮我\s*)?"
        r"(?:(?:看看|看下|查一下|查下|查询)\s*)?"
        r"(?:谁找过我|谁找我|谁联系过我|谁联系我)\s*[?？。]?"
    )
    if re.fullmatch(default_request, text):
        end = local_now.astimezone(dt_timezone.utc)
        return TimeWindow.from_utc(end - timedelta(hours=3), end, text)
    raise WindowTimeError("unsupported or ambiguous time range")


def _inclusive_source_seconds(window: TimeWindow) -> tuple[int, int]:
    epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    start = window.start.astimezone(timezone.utc) - epoch
    end = window.end.astimezone(timezone.utc) - epoch
    first = start.days * 86400 + start.seconds + bool(start.microseconds)
    last = end.days * 86400 + end.seconds
    return int(first), int(last)

