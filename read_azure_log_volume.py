# file: read_azure_log_volume.py
# version: v1.1

import argparse
import calendar
import configparser
import csv
import os
from collections import defaultdict
from datetime import datetime, timedelta

from azure.storage.blob import BlobServiceClient


GIB = 1024 ** 3
TIB = 1024 ** 4


def load_config(path="config.ini"):
    cfg = configparser.ConfigParser(interpolation=None)

    if not cfg.read(path):
        raise FileNotFoundError(f"Config file not found: {path}")

    return {
        "account_url": cfg["azure"]["account_url"],
        "container_name": cfg["azure"]["container_name"],
        "sas_token": cfg["azure"]["sas_token"],
    }


def date_range(start_date, end_date):
    current = start_date

    while current <= end_date:
        yield current
        current += timedelta(days=1)


def collect_daily_volumes(container, start_date, end_date):
    """
    Collect AM and IDM blob sizes for every day.

    Blob contents are never downloaded.
    """
    rows = []

    print("\nCollecting daily log volumes...")

    for day in date_range(start_date, end_date):
        date_string = day.strftime("%d-%m-%Y")

        totals = {
            "am_bytes": 0,
            "idm_bytes": 0,
            "am_blobs": 0,
            "idm_blobs": 0,
        }

        for log_type in ("am", "idm"):
            prefix = f"{log_type}_{date_string}"

            for blob in container.list_blobs(
                name_starts_with=prefix
            ):
                # Prefix is already specific enough for the expected
                # AM/IDM naming convention.
                size = int(blob.size or 0)

                totals[f"{log_type}_bytes"] += size
                totals[f"{log_type}_blobs"] += 1

        total_bytes = (
            totals["am_bytes"]
            + totals["idm_bytes"]
        )

        row = {
            "date": day,
            **totals,
            "total_bytes": total_bytes,
            "total_blobs": (
                totals["am_blobs"]
                + totals["idm_blobs"]
            ),
        }

        rows.append(row)

        print(
            f"{day.isoformat()}  "
            f"AM={totals['am_bytes'] / GIB:>9.2f} GiB  "
            f"IDM={totals['idm_bytes'] / GIB:>9.2f} GiB  "
            f"Total={total_bytes / GIB:>9.2f} GiB"
        )

    return rows


def is_complete_month(year, month, rows):
    """
    A month is complete only if every calendar day is present
    in the requested period.
    """
    expected_days = calendar.monthrange(
        year,
        month,
    )[1]

    dates = [
        row["date"]
        for row in rows
    ]

    return (
        len(rows) == expected_days
        and min(dates).day == 1
        and max(dates).day == expected_days
    )


def build_monthly_stats(daily_rows):
    """
    Aggregate daily data into monthly totals and average daily volume.

    Month-to-month growth is based on average daily volume,
    not raw monthly total.
    """
    grouped = defaultdict(list)

    for row in daily_rows:
        grouped[
            row["date"].strftime("%Y-%m")
        ].append(row)

    monthly = []
    previous_avg = None

    for month in sorted(grouped):
        rows = grouped[month]

        year, month_number = map(
            int,
            month.split("-")
        )

        am_bytes = sum(
            row["am_bytes"]
            for row in rows
        )

        idm_bytes = sum(
            row["idm_bytes"]
            for row in rows
        )

        total_bytes = (
            am_bytes
            + idm_bytes
        )

        average_daily = (
            total_bytes / len(rows)
        )

        growth_pct = None

        if previous_avg is not None and previous_avg > 0:
            growth_pct = (
                (average_daily / previous_avg) - 1
            ) * 100

        monthly.append(
            {
                "month": month,
                "days": len(rows),
                "complete": is_complete_month(
                    year,
                    month_number,
                    rows,
                ),
                "am_bytes": am_bytes,
                "idm_bytes": idm_bytes,
                "total_bytes": total_bytes,
                "average_daily_bytes": average_daily,
                "growth_pct": growth_pct,
            }
        )

        previous_avg = average_daily

    return monthly


def calculate_growth(monthly_rows):
    """
    Calculate headline growth using complete months only.

    Returns:
      arithmetic average month-over-month growth
      compound monthly growth rate
    """
    complete = [
        row
        for row in monthly_rows
        if row["complete"]
        and row["average_daily_bytes"] > 0
    ]

    if len(complete) < 2:
        return None, None

    ratios = []

    for previous, current in zip(
        complete,
        complete[1:],
    ):
        ratios.append(
            current["average_daily_bytes"]
            / previous["average_daily_bytes"]
        )

    growth_rates = [
        (ratio - 1) * 100
        for ratio in ratios
    ]

    average_growth = (
        sum(growth_rates)
        / len(growth_rates)
    )

    product = 1.0

    for ratio in ratios:
        product *= ratio

    compound_growth = (
        product ** (1 / len(ratios))
        - 1
    ) * 100

    return average_growth, compound_growth


def write_daily_csv(path, rows):
    with open(
        path,
        "w",
        encoding="utf-8",
        newline="",
    ) as file:
        writer = csv.writer(file)

        writer.writerow(
            [
                "date",
                "am_blobs",
                "idm_blobs",
                "total_blobs",
                "am_gib",
                "idm_gib",
                "total_gib",
            ]
        )

        for row in rows:
            writer.writerow(
                [
                    row["date"].isoformat(),
                    row["am_blobs"],
                    row["idm_blobs"],
                    row["total_blobs"],
                    round(
                        row["am_bytes"] / GIB,
                        3,
                    ),
                    round(
                        row["idm_bytes"] / GIB,
                        3,
                    ),
                    round(
                        row["total_bytes"] / GIB,
                        3,
                    ),
                ]
            )


def write_monthly_csv(path, rows):
    with open(
        path,
        "w",
        encoding="utf-8",
        newline="",
    ) as file:
        writer = csv.writer(file)

        writer.writerow(
            [
                "month",
                "days",
                "complete_month",
                "am_gib",
                "idm_gib",
                "total_gib",
                "total_tib",
                "average_daily_gib",
                "growth_pct",
            ]
        )

        for row in rows:
            writer.writerow(
                [
                    row["month"],
                    row["days"],
                    row["complete"],
                    round(
                        row["am_bytes"] / GIB,
                        3,
                    ),
                    round(
                        row["idm_bytes"] / GIB,
                        3,
                    ),
                    round(
                        row["total_bytes"] / GIB,
                        3,
                    ),
                    round(
                        row["total_bytes"] / TIB,
                        3,
                    ),
                    round(
                        row["average_daily_bytes"] / GIB,
                        3,
                    ),
                    (
                        round(
                            row["growth_pct"],
                            3,
                        )
                        if row["growth_pct"] is not None
                        else ""
                    ),
                ]
            )


def build_summary(
    start_date,
    end_date,
    daily_rows,
    monthly_rows,
    average_growth,
    compound_growth,
):
    am_total = sum(
        row["am_bytes"]
        for row in daily_rows
    )

    idm_total = sum(
        row["idm_bytes"]
        for row in daily_rows
    )

    total = (
        am_total
        + idm_total
    )

    daily_values = [
        row["total_bytes"]
        for row in daily_rows
    ]

    average_daily = (
        total / len(daily_rows)
        if daily_rows
        else 0
    )

    minimum_daily = (
        min(daily_values)
        if daily_values
        else 0
    )

    maximum_daily = (
        max(daily_values)
        if daily_values
        else 0
    )

    lines = [
        "Ping AIC Log Volume Analysis",
        "=" * 74,
        (
            f"Period:                 "
            f"{start_date.isoformat()} -> "
            f"{end_date.isoformat()}"
        ),
        f"Days analysed:          {len(daily_rows):,}",
        "",
        "OVERALL VOLUME",
        "-" * 74,
        (
            f"AM volume:              "
            f"{am_total / TIB:,.3f} TiB"
        ),
        (
            f"IDM volume:             "
            f"{idm_total / TIB:,.3f} TiB"
        ),
        (
            f"Total volume:           "
            f"{total / TIB:,.3f} TiB"
        ),
        (
            f"Average daily volume:   "
            f"{average_daily / GIB:,.2f} GiB"
        ),
        (
            f"Minimum daily volume:   "
            f"{minimum_daily / GIB:,.2f} GiB"
        ),
        (
            f"Maximum daily volume:   "
            f"{maximum_daily / GIB:,.2f} GiB"
        ),
        "",
        "MONTHLY TREND",
        "-" * 74,
        (
            f"{'Month':<10}"
            f"{'Days':>6}"
            f"{'Avg/day':>15}"
            f"{'Total':>15}"
            f"{'Growth':>12}"
            f"{'Status':>12}"
        ),
    ]

    for row in monthly_rows:
        growth = (
            f"{row['growth_pct']:+.2f}%"
            if row["growth_pct"] is not None
            else "-"
        )

        status = (
            "COMPLETE"
            if row["complete"]
            else "PARTIAL"
        )

        lines.append(
            f"{row['month']:<10}"
            f"{row['days']:>6}"
            f"{row['average_daily_bytes'] / GIB:>11.2f} GiB"
            f"{row['total_bytes'] / TIB:>11.3f} TiB"
            f"{growth:>12}"
            f"{status:>12}"
        )

    lines.extend(
        [
            "",
            "GROWTH SUMMARY",
            "-" * 74,
        ]
    )

    if average_growth is None:
        lines.append(
            "Not enough complete months "
            "to calculate monthly growth."
        )
    else:
        lines.append(
            f"Average monthly growth:  "
            f"{average_growth:+.2f}%"
        )

        lines.append(
            f"Compound monthly growth: "
            f"{compound_growth:+.2f}%"
        )

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Calculate Ping AIC AM + IDM daily and monthly "
            "log volumes using Azure Blob Storage metadata."
        )
    )

    parser.add_argument(
        "--start",
        required=True,
        help="Start date (DD-MM-YYYY)",
    )

    parser.add_argument(
        "--end",
        required=True,
        help="End date (DD-MM-YYYY)",
    )

    parser.add_argument(
        "--output-dir",
        default=".",
    )

    parser.add_argument(
        "--config",
        default="config.ini",
    )

    args = parser.parse_args()

    try:
        start_date = datetime.strptime(
            args.start,
            "%d-%m-%Y",
        ).date()

        end_date = datetime.strptime(
            args.end,
            "%d-%m-%Y",
        ).date()

    except ValueError:
        parser.error(
            "Dates must use DD-MM-YYYY"
        )

    if start_date > end_date:
        parser.error(
            "--start must not be later than --end"
        )

    config = load_config(
        args.config
    )

    container = BlobServiceClient(
        account_url=config["account_url"],
        credential=config["sas_token"],
    ).get_container_client(
        config["container_name"]
    )

    daily_rows = collect_daily_volumes(
        container,
        start_date,
        end_date,
    )

    monthly_rows = build_monthly_stats(
        daily_rows
    )

    average_growth, compound_growth = (
        calculate_growth(
            monthly_rows
        )
    )

    os.makedirs(
        args.output_dir,
        exist_ok=True,
    )

    run_id = datetime.now().strftime(
        "%Y%m%dT%H%M%S"
    )

    base = (
        f"log_volume_"
        f"{start_date:%Y%m%d}_to_"
        f"{end_date:%Y%m%d}_"
        f"{run_id}"
    )

    daily_path = os.path.join(
        args.output_dir,
        f"{base}_daily.csv",
    )

    monthly_path = os.path.join(
        args.output_dir,
        f"{base}_monthly.csv",
    )

    summary_path = os.path.join(
        args.output_dir,
        f"{base}.log",
    )

    write_daily_csv(
        daily_path,
        daily_rows,
    )

    write_monthly_csv(
        monthly_path,
        monthly_rows,
    )

    summary = build_summary(
        start_date,
        end_date,
        daily_rows,
        monthly_rows,
        average_growth,
        compound_growth,
    )

    with open(
        summary_path,
        "w",
        encoding="utf-8",
        newline="\n",
    ) as file:
        file.write(summary)
        file.write("\n")

    print("\n" + summary)

    print(
        f"\nDaily CSV:   {daily_path}"
    )

    print(
        f"Monthly CSV: {monthly_path}"
    )

    print(
        f"Summary:     {summary_path}"
    )


if __name__ == "__main__":
    main()
