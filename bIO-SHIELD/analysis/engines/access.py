from collections import defaultdict
from collections.abc import Mapping
from datetime import UTC, datetime

_RAPID_WINDOW_SECONDS = 300
_RAPID_DOWNLOAD_THRESHOLD = 3
_VOLUME_WINDOW_SECONDS = 600
_VOLUME_THRESHOLD = 10

_FLAG_NAMES = ("rapid_repeated_downloads", "unusual_hour", "new_ip_for_user", "high_volume_in_short_window")


def _get(record, key, default=None):
    if isinstance(record, Mapping):
        return record.get(key, default)
    return getattr(record, key, default)


def _normalize_events(events):
    if events is None:
        return []
    if isinstance(events, Mapping):
        return [events]
    try:
        return list(events)
    except TypeError:
        return []


def _parse_time(value):
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, bool):
        return None
    elif isinstance(value, (int, float)):
        try:
            parsed = datetime.fromtimestamp(float(value), tz=UTC)
        except (OverflowError, OSError, ValueError):
            return None
    elif isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            return None
    else:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _metadata(event):
    metadata = _get(event, "metadata", {})
    return metadata if isinstance(metadata, Mapping) else {}


def _event_time(event):
    for key in ("occurred_at", "timestamp"):
        parsed = _parse_time(_get(event, key))
        if parsed is not None:
            return parsed
    metadata = _metadata(event)
    for key in ("occurred_at", "timestamp"):
        parsed = _parse_time(metadata.get(key))
        if parsed is not None:
            return parsed
    return None


def _user_id(event):
    value = _get(event, "user_id")
    if value is None or str(value) == "":
        value = _get(event, "actor_label")
    if value is None or str(value) == "":
        user = _get(event, "user")
        if user is not None:
            value = _get(user, "email", None) or _get(user, "username", None) or _get(user, "pk", None)
    if value is None or str(value) == "":
        return "__unknown__"
    return str(value)


def _ip_address(event):
    value = _get(event, "ip_address")
    if not value:
        value = _metadata(event).get("ip_address")
    if value is None or str(value) == "":
        return None
    return str(value)


def _is_download(event):
    return "download" in str(_get(event, "action", "") or "").lower()


def _set_flag(flags, index, name, reason):
    detail = flags[index]
    if not detail[name]:
        detail[name] = True
    if reason not in detail["reasons"]:
        detail["reasons"].append(reason)


def detect_anomalies(events):
    records = _normalize_events(events)
    flags = {index: {name: False for name in _FLAG_NAMES} | {"reasons": []} for index in range(len(records))}
    by_user = defaultdict(list)
    times = {}
    addresses = {}
    for index, event in enumerate(records):
        user = _user_id(event)
        by_user[user].append(index)
        occurred_at = _event_time(event)
        if occurred_at is not None:
            times[index] = occurred_at
            if occurred_at.hour < 7 or occurred_at.hour >= 20:
                _set_flag(flags, index, "unusual_hour", "Event occurred outside the expected daytime window (UTC).")
        ip_address = _ip_address(event)
        if ip_address is not None:
            addresses[index] = ip_address
    missing_time = datetime.max.replace(tzinfo=UTC)
    for indices in by_user.values():
        timed_indices = sorted((index for index in indices if index in times), key=lambda index: (times[index], index))
        rapid_window = []
        for index in timed_indices:
            while rapid_window and (times[index] - times[rapid_window[0]]).total_seconds() > _RAPID_WINDOW_SECONDS:
                rapid_window.pop(0)
            rapid_window.append(index)
            downloads = [candidate for candidate in rapid_window if _is_download(records[candidate])]
            if len(downloads) >= _RAPID_DOWNLOAD_THRESHOLD:
                for candidate in downloads:
                    _set_flag(
                        flags,
                        candidate,
                        "rapid_repeated_downloads",
                        "Repeated download actions occurred within a five-minute window.",
                    )
        volume_window = []
        for index in timed_indices:
            while volume_window and (times[index] - times[volume_window[0]]).total_seconds() > _VOLUME_WINDOW_SECONDS:
                volume_window.pop(0)
            volume_window.append(index)
            if len(volume_window) >= _VOLUME_THRESHOLD:
                for candidate in volume_window:
                    _set_flag(
                        flags,
                        candidate,
                        "high_volume_in_short_window",
                        "Event volume exceeded the ten-minute activity threshold.",
                    )
        known_addresses = set()
        chronological = sorted(indices, key=lambda index: (times.get(index, missing_time), index))
        for index in chronological:
            ip_address = addresses.get(index)
            if ip_address is None or ip_address in known_addresses:
                continue
            if known_addresses:
                _set_flag(
                    flags,
                    index,
                    "new_ip_for_user",
                    "An IP address was observed for this user for the first time.",
                )
            known_addresses.add(ip_address)
    alert_definitions = (
        (
            "rapid_repeated_downloads",
            "HIGH",
            "Rapid repeated downloads",
            "Repeated download actions occurred within a short window.",
        ),
        (
            "high_volume_in_short_window",
            "HIGH",
            "High-volume activity",
            "Event volume exceeded the configured short-window threshold.",
        ),
        (
            "new_ip_for_user",
            "MODERATE",
            "New IP address",
            "An IP address was newly observed for the user.",
        ),
        (
            "unusual_hour",
            "MODERATE",
            "Unusual access hour",
            "Access occurred outside the expected daytime window (UTC).",
        ),
    )
    flag_metadata = {name: (severity, title) for name, severity, title, _ in alert_definitions}
    severity_rank = {"LOW": 0, "MODERATE": 1, "HIGH": 2, "CRITICAL": 3}
    for detail in flags.values():
        active_flags = [name for name in _FLAG_NAMES if detail[name]]
        if not active_flags:
            continue
        primary_flag = max(active_flags, key=lambda name: severity_rank[flag_metadata[name][0]])
        detail["severity"] = flag_metadata[primary_flag][0]
        detail["title"] = flag_metadata[primary_flag][1]
        detail["reason"] = "; ".join(detail["reasons"])
    alerts = []
    for flag_name, severity, title, reason in alert_definitions:
        grouped = defaultdict(list)
        for index, detail in flags.items():
            if detail[flag_name]:
                grouped[_user_id(records[index])].append(index)
        for user in sorted(grouped):
            event_indices = sorted(grouped[user])
            alerts.append(
                {
                    "severity": severity,
                    "title": title,
                    "reason": f"{len(event_indices)} event(s): {reason}",
                    "event_indices": event_indices,
                    "user_id": user,
                    "flag": flag_name,
                }
            )
    return flags, alerts


def monitor_access_events(events, **options):
    return detect_anomalies(events)
