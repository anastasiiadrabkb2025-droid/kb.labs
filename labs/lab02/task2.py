import csv
import json
import logging
import re
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


@dataclass
class CertStatus:
    domain: str
    issuer: str
    days_left: int
    status: str
    signature_alg: str
    is_weak_alg: bool


def parse_date(date_str: str) -> datetime:
    return datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)


def analyze_certificates(certs_file: Path, days_warning: int = 30) -> list[CertStatus]:
    if not certs_file.exists():
        logger.error(f"Файл {certs_file} не знайдено.")
        return []

    logger.info(f"Loading SSL certificates data from {certs_file}...")
    with open(certs_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    logger.info(f"Audited {len(data)} domain certificates.\n")
    now = datetime.now(timezone.utc)
    results: list[CertStatus] = []

    weak_alg_pattern = re.compile(r"(?i)sha1|md5")

    for item in data:
        domain = item.get("domain", "Unknown")
        issuer = item.get("issuer", "Unknown")
        valid_to = parse_date(item["validTo"])
        sig_alg = item.get("signatureAlgorithm", "Unknown")

        days_left = (valid_to - now).days
        is_weak = bool(weak_alg_pattern.search(sig_alg))

        if days_left < 0:
            status = "EXPIRED"
        elif days_left <= days_warning:
            status = "WARNING"
        else:
            status = "OK"

        if is_weak and status == "OK":
            status = "WEAK_ALG"

        results.append(
            CertStatus(
                domain=domain,
                issuer=issuer,
                days_left=days_left,
                status=status,
                signature_alg=sig_alg,
                is_weak_alg=is_weak,
            )
        )

    return results


def print_report(results: list[CertStatus], days_warning: int):
    print("=== Certificate Expiry & Safety Status ===")
    print(f"{'Domain':<28} {'Issuer':<15} {'Days Left':<10} {'Status':<10} {'Signature Alg'}")
    print("-" * 75)

    expired_cnt = 0
    warning_cnt = 0

    for c in results:
        status_str = f"{c.status} (WEAK)" if c.is_weak_alg and c.status == "EXPIRED" else c.status
        print(f"{c.domain:<28} {c.issuer:<15} {f'{c.days_left} days':<10} {status_str:<10} {c.signature_alg}")

        if c.status == "EXPIRED":
            expired_cnt += 1
        elif c.status == "WARNING":
            warning_cnt += 1

    print("\n=== Issuer Statistics ===")
    issuers = [c.issuer for c in results]
    for issuer, count in Counter(issuers).items():
        print(f"{issuer:<15} : {count}")

    print()
    if expired_cnt > 0 or warning_cnt > 0:
        logger.warning(
            f"{expired_cnt} certificate(s) EXPIRED! {warning_cnt} certificate(s) expiring within {days_warning} days!"
        )


def export_report(results: list[CertStatus], output_file: Path, fmt: str = "json"):
    output_file.parent.mkdir(parents=True, exist_ok=True)

    if fmt.lower() == "csv" or output_file.suffix == ".csv":
        with open(output_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Domain", "Issuer", "DaysLeft", "Status", "SignatureAlg", "IsWeakAlg"])
            for c in results:
                writer.writerow([c.domain, c.issuer, c.days_left, c.status, c.signature_alg, c.is_weak_alg])
    else:
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump([c.__dict__ for c in results], f, indent=2)

    logger.info(f"Report saved to {output_file}")


def run_analysis(certs_data: str, days_warning: int, output_report: str | None, fmt: str):
    certs_path = Path(certs_data)
    results = analyze_certificates(certs_path, days_warning)
    if not results:
        return

    print_report(results, days_warning)

    if output_report:
        export_report(results, Path(output_report), fmt)