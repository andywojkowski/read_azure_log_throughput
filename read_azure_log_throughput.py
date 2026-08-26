# file: read_azure_log_throughput.py

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
    r"am_(\d{2}-\d{2}-\d{4})-\d+-.*?_audit\.json"
)

INDEX_PATTERN = re.compile(
    r"^(?:am|idm)_(\d{2}-\d{2}-\d{4})-(\d+)-"
)


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
    Return the numeric sequence number from a blob name.
    """
    match = INDEX_PATTERN.match(name)

    if not match:
        return -1

    return int(match.group(2))


def filter_blobs_by_date(
    container,
    start_date: datetime,
    end_date: datetime,
) -> List[str]:
    """
    Find AM audit blobs for the requested date range.
    """
    filtered_blobs = []

    current_date = start_date.date()

    while current_date <= end_date.date():

        prefix = (
            f"am_{current_date.strftime('%d-%m-%Y')}"
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


def get_message_size(entry: dict) -> int:
    """
    Return the UTF-8 size of a log message in bytes.

    A compact JSON representation is used so the measurement reflects
    the data itself rather than pretty-printing whitespace.

    Example:

        {"timestamp":"...","payload":{...}}

    The result represents the normalized JSON message size rather than
    the exact byte range occupied by the entry inside the source blob.
    """
    serialized = json.dumps(
        entry,
        ensure_ascii=False,
        separators=(",", ":"),
    )

    return len(
        serialized.encode("utf-8")
    )


def initialize_minute_buckets(
    start_dt: datetime,
    end_dt: datetime,
) -> Dict[datetime, int]:
    """
    Create every minute bucket touched by the requested period.

    Minutes containing zero messages are deliberately included.
    """
    buckets: Dict[datetime, int] = {}

    current = floor_to_minute(start_dt)
    final = floor_to_minute(end_dt)

    while current <= final:
        buckets[current] = 0
        current += timedelta(minutes=1)

    return buckets


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
    start_dt: datetime,
    end_dt: datetime,
    messages_per_minute: Dict[datetime, int],
) -> Tuple[dict, bool]:
    """
    Count messages from one blob and collect message-size statistics.

    Returns:

        counters
        reached_end

    Because entries and blobs are chronologically ordered,
    reached_end=True allows the caller to stop processing later blobs.
    """
    print(f"\nProcessing {blob_name}")

    counters = {
        "entries_seen": 0,
        "entries_in_period": 0,
        "invalid_timestamps": 0,

        # Message-size statistics for this blob.
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

        # Entries are ordered oldest -> newest.
        if ts_dt > end_dt:
            reached_end = True
            break

        if ts_dt < start_dt:
            continue

        counters["entries_in_period"] += 1

        minute = floor_to_minute(ts_dt)

        if minute in messages_per_minute:
            messages_per_minute[minute] += 1

        # ----------------------------------------------------------
        # Message-size statistics
        # ----------------------------------------------------------

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


def calculate_statistics(
    messages_per_minute: Dict[datetime, int],
    start_dt: datetime,
    end_dt: datetime,
) -> dict:
    """
    Calculate throughput statistics from minute buckets.
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
        for minute, count in messages_per_minute.items()
        if count == minimum
    ]

    maximum_minutes = [
        minute
        for minute, count in messages_per_minute.items()
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
    message_size_count: int,
    message_size_total: int,
    message_size_min: Optional[int],
    message_size_max: Optional[int],
) -> dict:
    """
    Calculate overall message-size statistics.
    """
    if message_size_count == 0:
        return {
            "count": 0,
            "minimum": 0,
            "average": 0.0,
            "maximum": 0,
        }

    return {
        "count": message_size_count,
        "minimum": (
            message_size_min
            if message_size_min is not None
            else 0
        ),
        "average": (
            message_size_total
            / message_size_count
        ),
        "maximum": (
            message_size_max
            if message_size_max is not None
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
    Write the per-minute throughput table as CSV.

    Message-size statistics are intentionally not included here.
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
    blobs_processed: int,
    entries_seen: int,
    invalid_timestamps: int,
) -> None:
    """
    Write detailed JSON output.

    Message-size statistics are intentionally not included because
    they are summary-only metrics.
    """
    report = {
        "period": {
            "start": start_dt.isoformat(),
            "end": end_dt.isoformat(),
        },
        "summary": {
            "minutesCovered": statistics["minutes"],
            "totalMessages": statistics["total_messages"],
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
                for minute in statistics["minimum_minutes"]
            ],
            "maximumMinutes": [
                minute.isoformat()
                for minute in statistics["maximum_minutes"]
            ],
            "blobsProcessed": blobs_processed,
            "entriesSeen": entries_seen,
            "invalidTimestamps": invalid_timestamps,
        },
        "minutes": [
            {
                "minute": minute.isoformat(),
                "messages": count,
            }
            for minute, count in messages_per_minute.items()
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
    blobs_processed: int,
    entries_seen: int,
    invalid_timestamps: int,
) -> None:
    """
    Write a human-readable summary.
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
        f"Blobs processed:      "
        f"{blobs_processed:,}"
    )

    lines.append(
        f"Entries seen:         "
        f"{entries_seen:,}"
    )

    lines.append(
        f"Invalid timestamps:   "
        f"{invalid_timestamps:,}"
    )

    lines.append(
        f"Minutes covered:      "
        f"{statistics['minutes']:,}"
    )

    lines.append(
        f"Total messages:       "
        f"{statistics['total_messages']:,}"
    )

    lines.append("")

    lines.append(
        "MESSAGE THROUGHPUT"
    )

    lines.append(
        "-" * 60
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
        "MESSAGE SIZE"
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
    Print all per-minute counters to the console.
    """
    print("\nPER-MINUTE MESSAGE COUNTS")
    print("=" * 45)

    print(
        f"{'Minute':<22}"
        f"{'Messages':>15}"
    )

    print("-" * 45)

    for minute, count in messages_per_minute.items():

        print(
            f"{minute.strftime('%Y-%m-%d %H:%'):<22}"
            f"{count:>15,}"
        )


def main() -> int:

    parser = argparse.ArgumentParser(
        description=(
            "Calculate Ping AIC log-message throughput "
            "per minute and message-size statistics "
            "from Azure Blob Storage audit logs."
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
            "Print the complete per-minute throughput "
            "table to the console."
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
        "\nSearching blobs between "
        f"{start_dt} and {end_dt}"
    )

    try:
        blobs = filter_blobs_by_date(
            container,
            start_dt,
            end_dt,
        )

    except Exception as exc:
        print(
            "\nFailed to list Azure blobs:"
        )

        print(str(exc))

        return 1

    print(
        f"Found {len(blobs)} candidate blob(s)"
    )

    messages_per_minute = initialize_minute_buckets(
        start_dt=start_dt,
        end_dt=end_dt,
    )

    totals = {
        "entries_seen": 0,
        "entries_in_period": 0,
        "invalid_timestamps": 0,

        # Global message-size aggregation.
        "message_size_count": 0,
        "message_size_total": 0,
        "message_size_min": None,
        "message_size_max": None,
    }

    successfully_processed_blobs = []

    for blob_name in blobs:

        try:
            blob_counters, reached_end = process_blob(
                container=container,
                blob_name=blob_name,
                start_dt=start_dt,
                end_dt=end_dt,
                messages_per_minute=messages_per_minute,
            )

        except Exception as exc:

            print(
                f"\nERROR processing {blob_name}: "
                f"{exc}"
            )

            continue

        successfully_processed_blobs.append(
            blob_name
        )

        totals["entries_seen"] += (
            blob_counters["entries_seen"]
        )

        totals["entries_in_period"] += (
            blob_counters["entries_in_period"]
        )

        totals["invalid_timestamps"] += (
            blob_counters["invalid_timestamps"]
        )

        totals["message_size_count"] += (
            blob_counters["message_size_count"]
        )

        totals["message_size_total"] += (
            blob_counters["message_size_total"]
        )

        blob_min = blob_counters[
            "message_size_min"
        ]

        if blob_min is not None:
            if (
                totals["message_size_min"] is None
                or blob_min < totals["message_size_min"]
            ):
                totals["message_size_min"] = blob_min

        blob_max = blob_counters[
            "message_size_max"
        ]

        if blob_max is not None:
            if (
                totals["message_size_max"] is None
                or blob_max > totals["message_size_max"]
            ):
                totals["message_size_max"] = blob_max

        if reached_end:

            print(
                "\nEnd timestamp reached. "
                "Skipping remaining blobs."
            )

            break

    statistics = calculate_statistics(
        messages_per_minute=messages_per_minute,
        start_dt=start_dt,
        end_dt=end_dt,
    )

    message_size_statistics = (
        calculate_message_size_statistics(
            message_size_count=totals[
                "message_size_count"
            ],
            message_size_total=totals[
                "message_size_total"
            ],
            message_size_min=totals[
                "message_size_min"
            ],
            message_size_max=totals[
                "message_size_max"
            ],
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

    # Deliberately unchanged:
    # message-size metrics are summary-only.
    write_json_report(
        output_path=json_path,
        start_dt=start_dt,
        end_dt=end_dt,
        messages_per_minute=messages_per_minute,
        statistics=statistics,
        blobs_processed=len(
            successfully_processed_blobs
        ),
        entries_seen=totals["entries_seen"],
        invalid_timestamps=totals[
            "invalid_timestamps"
        ],
    )

    write_summary_log(
        output_path=summary_path,
        start_dt=start_dt,
        end_dt=end_dt,
        statistics=statistics,
        message_size_statistics=message_size_statistics,
        blobs_processed=len(
            successfully_processed_blobs
        ),
        entries_seen=totals["entries_seen"],
        invalid_timestamps=totals[
            "invalid_timestamps"
        ],
    )

    if args.verbose:
        print_verbose_minute_table(
            messages_per_minute
        )

    print("\n" + "=" * 60)
    print("LOG THROUGHPUT STATISTICS")
    print("=" * 60)

    print(
        f"Period:             "
        f"{start_dt} -> {end_dt}"
    )

    print(
        f"Minutes covered:    "
        f"{statistics['minutes']:,}"
    )

    print(
        f"Total messages:     "
        f"{statistics['total_messages']:,}"
    )

    print("-" * 60)

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

    print("\n" + "=" * 60)
    print("MESSAGE SIZE STATISTICS")
    print("=" * 60)

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

    print("\n" + "-" * 60)

    print(
        f"Blobs processed:    "
        f"{len(successfully_processed_blobs):,}"
    )

    print(
        f"Entries inspected:  "
        f"{totals['entries_seen']:,}"
    )

    if totals["invalid_timestamps"]:

        print(
            f"Invalid timestamps: "
            f"{totals['invalid_timestamps']:,}"
        )

    print("\nMinimum throughput observed at:")

    for minute in statistics["minimum_minutes"]:
        print(
            f"  {minute.strftime('%Y-%m-%d %H:%M')}"
        )

    print("Maximum throughput observed at:")

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
