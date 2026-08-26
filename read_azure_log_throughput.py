# file: read_azure_log_throughput.py
# version: v1.0

import argparse
import configparser
import csv
import json
import os
import re
from datetime import datetime, timedelta
from typing import Dict, Iterator, List, Optional, Tuple

from azure.storage.blob import BlobServiceClient


DATE_PATTERN = re.compile(
    r"(?:am|idm)_(\d{2}-\d{2}-\d{4})-\d+-.*?_audit\.json"
)

INDEX_PATTERN = re.compile(
    r"^(?:am|idm)_(\d{2}-\d{2}-\d{4})-(\d+)-"
)

LOG_TYPES = ("am", "idm")


def load_config(path: str = "config.ini") -> dict:
    """
    Load Azure Blob Storage configuration.
    """
    cfg = configparser.ConfigParser(interpolation=None)

    if not cfg.read(path):
        raise FileNotFoundError(
            f"Configuration file not found: {path}"
        )

    if "azure" not in cfg:
        raise KeyError(
            f"Missing [azure] section in configuration file: {path}"
        )

    required_keys = (
        "account_url",
        "container_name",
        "sas_token",
    )

    missing = [
        key
        for key in required_keys
        if key not in cfg["azure"]
    ]

    if missing:
        raise KeyError(
            "Missing Azure configuration values: "
            + ", ".join(missing)
        )

    return {
        "account_url": cfg["azure"]["account_url"],
        "container_name": cfg["azure"]["container_name"],
        "sas_token": cfg["azure"]["sas_token"],
    }


def extract_json_objects(text: str) -> Iterator[str]:
    """
    Extract top-level JSON objects from text.

    Handles:
      - JSON strings
      - escaped quotes
      - braces inside strings
    """
    brace_level = 0
    start = None
    in_string = False
    escaped = False

    for index, char in enumerate(text):

        if in_string:
            if escaped:
                escaped = False
                continue

            if char == "\\":
                escaped = True
                continue

            if char == '"':
                in_string = False

            continue

        if char == '"':
            in_string = True
            continue

        if char == "{":
            if brace_level == 0:
                start = index

            brace_level += 1
            continue

        if char == "}":
            if brace_level == 0:
                continue

            brace_level -= 1

            if brace_level == 0 and start is not None:
                yield text[start:index + 1]
                start = None


def extract_blob_index(name: str) -> int:
    """
    Return the numeric sequence number from an AM or IDM blob name.
    """
    match = INDEX_PATTERN.match(name)

    if not match:
        return -1

    return int(match.group(2))


def filter_blobs_by_date(
    container,
    log_type: str,
    start_date: datetime,
    end_date: datetime,
) -> List[str]:
    """
    Find audit blobs for one independent log stream.

    log_type must be either:
      - am
      - idm

    AM and IDM blobs are deliberately discovered and sorted separately
    because their sequence numbers represent independent streams.
    """
    if log_type not in LOG_TYPES:
        raise ValueError(
            f"Unsupported log type: {log_type}"
        )

    filtered_blobs = []

    current_date = start_date.date()

    while current_date <= end_date.date():

        prefix = (
            f"{log_type}_"
            f"{current_date.strftime('%d-%m-%Y')}"
        )

        daily_blobs = list(
            container.list_blobs(
                name_starts_with=prefix
            )
        )

        daily_blobs.sort(
            key=lambda blob: extract_blob_index(blob.name)
        )

        for blob in daily_blobs:

            match = DATE_PATTERN.match(blob.name)

            if not match:
                continue

            blob_date = datetime.strptime(
                match.group(1),
                "%d-%m-%Y",
            )

            if (
                start_date.date()
                <= blob_date.date()
                <= end_date.date()
            ):
                filtered_blobs.append(blob.name)

        current_date += timedelta(days=1)

    return filtered_blobs


def parse_timestamp(value: object) -> Optional[datetime]:
    """
    Parse a Ping AIC ISO timestamp.

    Supported examples:

        2026-08-26T10:15:23
        2026-08-26T10:15:23.123
        2026-08-26T10:15:23.123Z
        2026-08-26T10:15:23+00:00
    """
    if not isinstance(value, str):
        return None

    value = value.strip()

    if not value:
        return None

    try:
        normalized = value

        if normalized.endswith("Z"):
            normalized = normalized[:-1] + "+00:00"

        parsed = datetime.fromisoformat(normalized)

        # Preserve compatibility with naive CLI timestamps.
        if parsed.tzinfo is not None:
            parsed = parsed.replace(tzinfo=None)

        return parsed

    except ValueError:
        return None


def floor_to_minute(value: datetime) -> datetime:
    """
    Truncate a datetime to the beginning of its minute.
    """
    return value.replace(
        second=0,
        microsecond=0,
    )


def initialize_minute_buckets(
    start_dt: datetime,
    end_dt: datetime,
) -> Dict[datetime, int]:
    """
    Create every minute bucket touched by the requested period.

    Minutes with zero log messages are deliberately retained.
    """
    buckets: Dict[datetime, int] = {}

    current = floor_to_minute(start_dt)
    final = floor_to_minute(end_dt)

    while current <= final:
        buckets[current] = 0
        current += timedelta(minutes=1)

    return buckets


def get_message_size(entry: dict) -> int:
    """
    Calculate normalized UTF-8 log-message size in bytes.

    A compact JSON representation is used so whitespace introduced by
    formatting does not affect the measurement.

    This measures the normalized JSON entry, rather than its exact byte
    range in the original Azure blob.
    """
    serialized = json.dumps(
        entry,
        ensure_ascii=False,
        separators=(",", ":"),
    )

    return len(
        serialized.encode("utf-8")
    )


def iter_blob_entries(
    container,
    blob_name: str,
) -> Iterator[dict]:
    """
    Download one blob and yield individual Ping AIC result entries.
    """
    blob_client = container.get_blob_client(blob_name)

    content = (
        blob_client
        .download_blob()
        .readall()
        .decode("utf-8")
    )

    for object_text in extract_json_objects(content):

        try:
            parsed = json.loads(object_text)

        except json.JSONDecodeError:
            continue

        result = parsed.get("result")

        if not isinstance(result, list):
            continue

        for entry in result:

            if isinstance(entry, dict):
                yield entry


def process_blob(
    container,
    blob_name: str,
    log_type: str,
    start_dt: datetime,
    end_dt: datetime,
    messages_per_minute: Dict[datetime, int],
) -> Tuple[dict, bool]:
    """
    Process one blob from one log stream.

    Returns:

        counters
        reached_end

    reached_end is scoped to the current stream.

    For example, reaching --end while processing AM blobs must stop
    later AM blobs but must NOT prevent IDM blobs from being processed.
    """
    print(
        f"\n[{log_type.upper()}] "
        f"Processing {blob_name}"
    )

    counters = {
        "entries_seen": 0,
        "entries_in_period": 0,
        "invalid_timestamps": 0,
        "message_size_count": 0,
        "message_size_total": 0,
        "message_size_min": None,
        "message_size_max": None,
    }

    reached_end = False

    for entry in iter_blob_entries(
        container,
        blob_name,
    ):
        counters["entries_seen"] += 1

        ts_dt = parse_timestamp(
            entry.get("timestamp")
        )

        if ts_dt is None:
            counters["invalid_timestamps"] += 1
            continue

        # Entries inside each stream are ordered oldest -> newest.
        if ts_dt > end_dt:
            reached_end = True
            break

        if ts_dt < start_dt:
            continue

        counters["entries_in_period"] += 1

        minute = floor_to_minute(ts_dt)

        if minute in messages_per_minute:
            messages_per_minute[minute] += 1

        message_size = get_message_size(entry)

        counters["message_size_count"] += 1
        counters["message_size_total"] += message_size

        if (
            counters["message_size_min"] is None
            or message_size < counters["message_size_min"]
        ):
            counters["message_size_min"] = message_size

        if (
            counters["message_size_max"] is None
            or message_size > counters["message_size_max"]
        ):
            counters["message_size_max"] = message_size

    print(
        f"  {counters['entries_in_period']:,} "
        "messages counted"
    )

    return counters, reached_end


def merge_counters(
    target: dict,
    source: dict,
) -> None:
    """
    Merge one blob's counters into a stream/global counter dictionary.
    """
    target["entries_seen"] += (
        source["entries_seen"]
    )

    target["entries_in_period"] += (
        source["entries_in_period"]
    )

    target["invalid_timestamps"] += (
        source["invalid_timestamps"]
    )

    target["message_size_count"] += (
        source["message_size_count"]
    )

    target["message_size_total"] += (
        source["message_size_total"]
    )

    source_min = source["message_size_min"]

    if source_min is not None:
        if (
            target["message_size_min"] is None
            or source_min < target["message_size_min"]
        ):
            target["message_size_min"] = source_min

    source_max = source["message_size_max"]

    if source_max is not None:
        if (
            target["message_size_max"] is None
            or source_max > target["message_size_max"]
        ):
            target["message_size_max"] = source_max


def new_counter_set() -> dict:
    """
    Create an empty statistics accumulator.
    """
    return {
        "entries_seen": 0,
        "entries_in_period": 0,
        "invalid_timestamps": 0,
        "message_size_count": 0,
        "message_size_total": 0,
        "message_size_min": None,
        "message_size_max": None,
    }


def process_log_stream(
    container,
    log_type: str,
    blobs: List[str],
    start_dt: datetime,
    end_dt: datetime,
    messages_per_minute: Dict[datetime, int],
) -> Tuple[dict, List[str]]:
    """
    Process one independent log stream.

    AM and IDM are handled separately because their blob indices and
    timestamp progression are independent.

    Both streams write into the same minute buckets, which automatically
    produces combined AM + IDM throughput.
    """
    stream_totals = new_counter_set()
    successfully_processed_blobs = []

    print(
        f"\n{'=' * 60}"
    )

    print(
        f"PROCESSING {log_type.upper()} LOG STREAM"
    )

    print(
        f"{'=' * 60}"
    )

    print(
        f"Found {len(blobs)} candidate "
        f"{log_type.upper()} blob(s)"
    )

    for blob_name in blobs:

        try:
            blob_counters, reached_end = process_blob(
                container=container,
                blob_name=blob_name,
                log_type=log_type,
                start_dt=start_dt,
                end_dt=end_dt,
                messages_per_minute=messages_per_minute,
            )

        except Exception as exc:

            print(
                f"\nERROR processing "
                f"{blob_name}: {exc}"
            )

            continue

        successfully_processed_blobs.append(
            blob_name
        )

        merge_counters(
            stream_totals,
            blob_counters,
        )

        if reached_end:

            print(
                f"\n[{log_type.upper()}] "
                "End timestamp reached. "
                f"Skipping remaining "
                f"{log_type.upper()} blobs."
            )

            break

    print(
        f"\n[{log_type.upper()}] "
        "Stream total: "
        f"{stream_totals['entries_in_period']:,} "
        "messages"
    )

    print(
        f"[{log_type.upper()}] "
        "Blobs processed: "
        f"{len(successfully_processed_blobs):,}"
    )

    return (
        stream_totals,
        successfully_processed_blobs,
    )


def calculate_statistics(
    messages_per_minute: Dict[datetime, int],
    start_dt: datetime,
    end_dt: datetime,
) -> dict:
    """
    Calculate combined AM + IDM throughput statistics.
    """
    values = list(
        messages_per_minute.values()
    )

    if not values:
        return {
            "minutes": 0,
            "total_messages": 0,
            "minimum_per_minute": 0,
            "average_per_minute": 0.0,
            "maximum_per_minute": 0,
            "minimum_minutes": [],
            "maximum_minutes": [],
            "period_seconds": 0.0,
            "average_per_second": 0.0,
        }

    minimum = min(values)
    maximum = max(values)

    total_messages = sum(values)

    average = (
        total_messages / len(values)
    )

    minimum_minutes = [
        minute
        for minute, count
        in messages_per_minute.items()
        if count == minimum
    ]

    maximum_minutes = [
        minute
        for minute, count
        in messages_per_minute.items()
        if count == maximum
    ]

    period_seconds = max(
        (end_dt - start_dt).total_seconds(),
        0.0,
    )

    average_per_second = (
        total_messages / period_seconds
        if period_seconds > 0
        else float(total_messages)
    )

    return {
        "minutes": len(values),
        "total_messages": total_messages,
        "minimum_per_minute": minimum,
        "average_per_minute": average,
        "maximum_per_minute": maximum,
        "minimum_minutes": minimum_minutes,
        "maximum_minutes": maximum_minutes,
        "period_seconds": period_seconds,
        "average_per_second": average_per_second,
    }


def calculate_message_size_statistics(
    counters: dict,
) -> dict:
    """
    Calculate message-size statistics from aggregated counters.
    """
    count = counters["message_size_count"]

    if count == 0:
        return {
            "count": 0,
            "minimum": 0,
            "average": 0.0,
            "maximum": 0,
        }

    return {
        "count": count,
        "minimum": (
            counters["message_size_min"]
            if counters["message_size_min"] is not None
            else 0
        ),
        "average": (
            counters["message_size_total"]
            / count
        ),
        "maximum": (
            counters["message_size_max"]
            if counters["message_size_max"] is not None
            else 0
        ),
    }


def bytes_to_kib(value: float) -> float:
    """
    Convert bytes to KiB.
    """
    return value / 1024.0


def write_csv_report(
    output_path: str,
    messages_per_minute: Dict[datetime, int],
) -> None:
    """
    Write combined AM + IDM per-minute throughput as CSV.
    """
    with open(
        output_path,
        "w",
        encoding="utf-8",
        newline="",
    ) as file:

        writer = csv.writer(file)

        writer.writerow(
            [
                "minute",
                "messages",
            ]
        )

        for minute, count in messages_per_minute.items():

            writer.writerow(
                [
                    minute.isoformat(),
                    count,
                ]
            )


def write_json_report(
    output_path: str,
    start_dt: datetime,
    end_dt: datetime,
    messages_per_minute: Dict[datetime, int],
    statistics: dict,
    am_totals: dict,
    idm_totals: dict,
    am_blobs_processed: int,
    idm_blobs_processed: int,
) -> None:
    """
    Write combined throughput JSON.

    Message-size statistics remain summary-only.
    """
    report = {
        "period": {
            "start": start_dt.isoformat(),
            "end": end_dt.isoformat(),
        },
        "summary": {
            "minutesCovered": statistics["minutes"],
            "totalMessages": statistics["total_messages"],
            "amMessages": am_totals["entries_in_period"],
            "idmMessages": idm_totals["entries_in_period"],
            "minimumMessagesPerMinute": (
                statistics["minimum_per_minute"]
            ),
            "averageMessagesPerMinute": round(
                statistics["average_per_minute"],
                2,
            ),
            "maximumMessagesPerMinute": (
                statistics["maximum_per_minute"]
            ),
            "averageMessagesPerSecond": round(
                statistics["average_per_second"],
                2,
            ),
            "minimumMinutes": [
                minute.isoformat()
                for minute
                in statistics["minimum_minutes"]
            ],
            "maximumMinutes": [
                minute.isoformat()
                for minute
                in statistics["maximum_minutes"]
            ],
            "amBlobsProcessed": am_blobs_processed,
            "idmBlobsProcessed": idm_blobs_processed,
        },
        "minutes": [
            {
                "minute": minute.isoformat(),
                "messages": count,
            }
            for minute, count
            in messages_per_minute.items()
        ],
    }

    with open(
        output_path,
        "w",
        encoding="utf-8",
        newline="\n",
    ) as file:

        json.dump(
            report,
            file,
            indent=2,
            ensure_ascii=False,
        )

        file.write("\n")


def write_summary_log(
    output_path: str,
    start_dt: datetime,
    end_dt: datetime,
    statistics: dict,
    message_size_statistics: dict,
    am_totals: dict,
    idm_totals: dict,
    am_blobs_processed: int,
    idm_blobs_processed: int,
) -> None:
    """
    Write the human-readable combined summary.
    """
    lines = []

    lines.append(
        "Ping AIC Log Throughput Statistics"
    )

    lines.append(
        "=" * 60
    )

    lines.append(
        f"Start: {start_dt.isoformat()}"
    )

    lines.append(
        f"End:   {end_dt.isoformat()}"
    )

    lines.append("")

    lines.append(
        "SOURCE BREAKDOWN"
    )

    lines.append(
        "-" * 60
    )

    lines.append(
        f"AM messages:          "
        f"{am_totals['entries_in_period']:,}"
    )

    lines.append(
        f"IDM messages:         "
        f"{idm_totals['entries_in_period']:,}"
    )

    lines.append(
        f"Total messages:       "
        f"{statistics['total_messages']:,}"
    )

    lines.append("")

    lines.append(
        f"AM blobs processed:   "
        f"{am_blobs_processed:,}"
    )

    lines.append(
        f"IDM blobs processed:  "
        f"{idm_blobs_processed:,}"
    )

    lines.append(
        f"Total blobs:          "
        f"{am_blobs_processed + idm_blobs_processed:,}"
    )

    lines.append("")

    lines.append(
        f"AM invalid timestamps:  "
        f"{am_totals['invalid_timestamps']:,}"
    )

    lines.append(
        f"IDM invalid timestamps: "
        f"{idm_totals['invalid_timestamps']:,}"
    )

    lines.append("")

    lines.append(
        "COMBINED MESSAGE THROUGHPUT"
    )

    lines.append(
        "-" * 60
    )

    lines.append(
        f"Minutes covered:      "
        f"{statistics['minutes']:,}"
    )

    lines.append(
        f"Minimum / minute:     "
        f"{statistics['minimum_per_minute']:,}"
    )

    lines.append(
        f"Average / minute:     "
        f"{statistics['average_per_minute']:,.2f}"
    )

    lines.append(
        f"Maximum / minute:     "
        f"{statistics['maximum_per_minute']:,}"
    )

    lines.append(
        f"Average / second:     "
        f"{statistics['average_per_second']:,.2f}"
    )

    lines.append("")

    lines.append(
        "COMBINED MESSAGE SIZE"
    )

    lines.append(
        "-" * 60
    )

    lines.append(
        f"Minimum message size: "
        f"{message_size_statistics['minimum']:,} bytes "
        f"({bytes_to_kib(message_size_statistics['minimum']):,.2f} KiB)"
    )

    lines.append(
        f"Average message size: "
        f"{message_size_statistics['average']:,.2f} bytes "
        f"({bytes_to_kib(message_size_statistics['average']):,.2f} KiB)"
    )

    lines.append(
        f"Maximum message size: "
        f"{message_size_statistics['maximum']:,} bytes "
        f"({bytes_to_kib(message_size_statistics['maximum']):,.2f} KiB)"
    )

    lines.append("")

    lines.append(
        "Minimum throughput observed at:"
    )

    for minute in statistics["minimum_minutes"]:
        lines.append(
            f"  {minute.isoformat()}"
        )

    lines.append(
        "Maximum throughput observed at:"
    )

    for minute in statistics["maximum_minutes"]:
        lines.append(
            f"  {minute.isoformat()}"
        )

    with open(
        output_path,
        "w",
        encoding="utf-8",
        newline="\n",
    ) as file:

        file.write(
            "\n".join(lines)
        )

        file.write("\n")


def print_verbose_minute_table(
    messages_per_minute: Dict[datetime, int],
) -> None:
    """
    Print combined AM + IDM per-minute counters.
    """
    print(
        "\nCOMBINED PER-MINUTE MESSAGE COUNTS"
    )

    print(
        "=" * 45
    )

    print(
        f"{'Minute':<22}"
        f"{'Messages':>15}"
    )

    print(
        "-" * 45
    )

    for minute, count in messages_per_minute.items():

        print(
            f"{minute.strftime('%Y-%m-%d %H:%'):<22}"
            f"{count:>15,}"
        )


def main() -> int:

    parser = argparse.ArgumentParser(
        description=(
            "Calculate combined Ping AIC AM + IDM log-message "
            "throughput and message-size statistics from "
            "Azure Blob Storage audit logs."
        )
    )

    parser.add_argument(
        "--start",
        required=True,
        help=(
            "Start timestamp "
            "(DD-MM-YYYYTHH:MM:SS)"
        ),
    )

    parser.add_argument(
        "--end",
        required=True,
        help=(
            "End timestamp "
            "(DD-MM-YYYYTHH:MM:SS)"
        ),
    )

    parser.add_argument(
        "--output-dir",
        default=".",
        help=(
            "Directory for generated reports"
        ),
    )

    parser.add_argument(
        "--config",
        default="config.ini",
        help=(
            "Path to configuration file"
        ),
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        help=(
            "Print the complete combined per-minute "
            "throughput table."
        ),
    )

    args = parser.parse_args()

    try:
        start_dt = datetime.strptime(
            args.start,
            "%d-%m-%YT%H:%M:%S",
        )

        end_dt = datetime.strptime(
            args.end,
            "%d-%m-%YT%H:%M:%S",
        )

    except ValueError:
        parser.error(
            "Invalid date format. "
            "Expected DD-MM-YYYYTHH:MM:SS"
        )

    if start_dt > end_dt:
        parser.error(
            "--start must be earlier than or equal to --end"
        )

    os.makedirs(
        args.output_dir,
        exist_ok=True,
    )

    config = load_config(
        args.config
    )

    blob_service = BlobServiceClient(
        account_url=config["account_url"],
        credential=config["sas_token"],
    )

    container = blob_service.get_container_client(
        config["container_name"]
    )

    print(
        "\nSearching AM and IDM blobs between "
        f"{start_dt} and {end_dt}"
    )

    try:
        am_blobs = filter_blobs_by_date(
            container=container,
            log_type="am",
            start_date=start_dt,
            end_date=end_dt,
        )

        idm_blobs = filter_blobs_by_date(
            container=container,
            log_type="idm",
            start_date=start_dt,
            end_date=end_dt,
        )

    except Exception as exc:

        print(
            "\nFailed to list Azure blobs:"
        )

        print(
            str(exc)
        )

        return 1

    print(
        f"Found {len(am_blobs)} AM candidate blob(s)"
    )

    print(
        f"Found {len(idm_blobs)} IDM candidate blob(s)"
    )

    # Shared buckets intentionally combine AM and IDM.
    messages_per_minute = initialize_minute_buckets(
        start_dt=start_dt,
        end_dt=end_dt,
    )

    # ----------------------------------------------------------
    # AM
    # ----------------------------------------------------------

    am_totals, processed_am_blobs = process_log_stream(
        container=container,
        log_type="am",
        blobs=am_blobs,
        start_dt=start_dt,
        end_dt=end_dt,
        messages_per_minute=messages_per_minute,
    )

    # ----------------------------------------------------------
    # IDM
    # ----------------------------------------------------------

    idm_totals, processed_idm_blobs = process_log_stream(
        container=container,
        log_type="idm",
        blobs=idm_blobs,
        start_dt=start_dt,
        end_dt=end_dt,
        messages_per_minute=messages_per_minute,
    )

    # ----------------------------------------------------------
    # Combine stream-level message size accumulators.
    # ----------------------------------------------------------

    combined_totals = new_counter_set()

    merge_counters(
        combined_totals,
        am_totals,
    )

    merge_counters(
        combined_totals,
        idm_totals,
    )

    # ----------------------------------------------------------
    # Final combined statistics.
    # ----------------------------------------------------------

    statistics = calculate_statistics(
        messages_per_minute=messages_per_minute,
        start_dt=start_dt,
        end_dt=end_dt,
    )

    message_size_statistics = (
        calculate_message_size_statistics(
            combined_totals
        )
    )

    start_str = start_dt.strftime(
        "%y%m%dT%H%M%S"
    )

    end_str = end_dt.strftime(
        "%y%m%dT%H%M%S"
    )

    run_id = datetime.now().strftime(
        "%Y%m%dT%H%M%S"
    )

    base_name = (
        f"log_throughput_"
        f"{start_str}_to_{end_str}_"
        f"{run_id}"
    )

    csv_path = os.path.join(
        args.output_dir,
        f"{base_name}.csv",
    )

    json_path = os.path.join(
        args.output_dir,
        f"{base_name}.json",
    )

    summary_path = os.path.join(
        args.output_dir,
        f"{base_name}.log",
    )

    write_csv_report(
        output_path=csv_path,
        messages_per_minute=messages_per_minute,
    )

    write_json_report(
        output_path=json_path,
        start_dt=start_dt,
        end_dt=end_dt,
        messages_per_minute=messages_per_minute,
        statistics=statistics,
        am_totals=am_totals,
        idm_totals=idm_totals,
        am_blobs_processed=len(
            processed_am_blobs
        ),
        idm_blobs_processed=len(
            processed_idm_blobs
        ),
    )

    write_summary_log(
        output_path=summary_path,
        start_dt=start_dt,
        end_dt=end_dt,
        statistics=statistics,
        message_size_statistics=message_size_statistics,
        am_totals=am_totals,
        idm_totals=idm_totals,
        am_blobs_processed=len(
            processed_am_blobs
        ),
        idm_blobs_processed=len(
            processed_idm_blobs
        ),
    )

    if args.verbose:
        print_verbose_minute_table(
            messages_per_minute
        )

    # ----------------------------------------------------------
    # Console summary
    # ----------------------------------------------------------

    print(
        "\n" + "=" * 60
    )

    print(
        "COMBINED LOG THROUGHPUT STATISTICS"
    )

    print(
        "=" * 60
    )

    print(
        f"Period:             "
        f"{start_dt} -> {end_dt}"
    )

    print("")

    print(
        f"AM messages:        "
        f"{am_totals['entries_in_period']:,}"
    )

    print(
        f"IDM messages:       "
        f"{idm_totals['entries_in_period']:,}"
    )

    print(
        f"Total messages:     "
        f"{statistics['total_messages']:,}"
    )

    print(
        f"Minutes covered:    "
        f"{statistics['minutes']:,}"
    )

    print(
        "-" * 60
    )

    print(
        f"Minimum / minute:   "
        f"{statistics['minimum_per_minute']:,}"
    )

    print(
        f"Average / minute:   "
        f"{statistics['average_per_minute']:,.2f}"
    )

    print(
        f"Maximum / minute:   "
        f"{statistics['maximum_per_minute']:,}"
    )

    print(
        f"Average / second:   "
        f"{statistics['average_per_second']:,.2f}"
    )

    print(
        "\n" + "=" * 60
    )

    print(
        "COMBINED MESSAGE SIZE STATISTICS"
    )

    print(
        "=" * 60
    )

    print(
        f"Minimum message size: "
        f"{message_size_statistics['minimum']:,} bytes "
        f"({bytes_to_kib(message_size_statistics['minimum']):,.2f} KiB)"
    )

    print(
        f"Average message size: "
        f"{message_size_statistics['average']:,.2f} bytes "
        f"({bytes_to_kib(message_size_statistics['average']):,.2f} KiB)"
    )

    print(
        f"Maximum message size: "
        f"{message_size_statistics['maximum']:,} bytes "
        f"({bytes_to_kib(message_size_statistics['maximum']):,.2f} KiB)"
    )

    print(
        "\n" + "-" * 60
    )

    print(
        f"AM blobs processed:  "
        f"{len(processed_am_blobs):,}"
    )

    print(
        f"IDM blobs processed: "
        f"{len(processed_idm_blobs):,}"
    )

    print(
        f"Total blobs:         "
        f"{len(processed_am_blobs) + len(processed_idm_blobs):,}"
    )

    print(
        "\nMinimum throughput observed at:"
    )

    for minute in statistics["minimum_minutes"]:
        print(
            f"  {minute.strftime('%Y-%m-%d %H:%M')}"
        )

    print(
        "Maximum throughput observed at:"
    )

    for minute in statistics["maximum_minutes"]:
        print(
            f"  {minute.strftime('%Y-%m-%d %H:%M')}"
        )

    print(
        f"\nCSV report:     {csv_path}"
    )

    print(
        f"JSON report:    {json_path}"
    )

    print(
        f"Summary report: {summary_path}"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
