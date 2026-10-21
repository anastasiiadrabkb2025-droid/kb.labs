import csv
import json
import logging
import re
from collections import Counter
from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class CertStatus:
    domain: str
    issuer: str
    days_left: int
    status: str
    signature_alg: str
    is_weak_alg: bool


def load_certificates(certs_path: Path) -> list[dict]:
    """Завантаження даних про сертифікати з JSON-файлу з обробкою винятків."""
    try:
        if not certs_path.exists():
            raise FileNotFoundError(f"Файл за шляхом '{certs_path}' не існує.")

        with open(certs_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            if not isinstance(data, list):
                raise TypeError("Вхідні дані JSON повинні бути списком об'єктів.")
            return data

    except FileNotFoundError as e:
        logger.error(f"[Помилка файлу] {e}")
    except json.JSONDecodeError as e:
        logger.error(f"[Помилка JSON] Файл '{certs_path}' містить некоректний JSON: {e}")
    except PermissionError:
        logger.error(f"[Помилка доступу] Немає прав для читання файлу '{certs_path}'.")
    except Exception as e:  # noqa: BLE001
        logger.error(f"[Несподівана помилка] Не вдалося завантажити сертифікати: {e}")

    return []


def analyze_certificates(certs_path: Path, days_warning: int = 30) -> list[CertStatus]:
    """Основна функція аналізу сертифікатів."""
    certs = load_certificates(certs_path)
    results = []
    today = datetime.now(timezone.utc).date()
    weak_alg_pattern = re.compile(r"(?i)sha1|md5")

    for item in certs:
        try:
            domain = item.get("domain", "Unknown")
            issuer = item.get("issuer", "Unknown")
            valid_to_str = item.get("validTo", "")
            sig_alg = item.get("signatureAlgorithm", "")

            valid_to_date = date.fromisoformat(valid_to_str)
            days_left = (valid_to_date - today).days

            if days_left < 0:
                status = "EXPIRED"
            elif days_left <= days_warning:
                status = "WARNING"
            else:
                status = "OK"

            is_weak = bool(weak_alg_pattern.search(sig_alg))

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
        except (ValueError, KeyError, TypeError) as e:
            logger.error(f"[Помилка обробки елемента] Не вдалося обробити запис {item}: {e}")
        except Exception as e:  # noqa: BLE001
            logger.error(f"[Несподівана помилка] {e}")

    return results


def print_report(results: list[CertStatus], days_warning: int) -> None:
    """Вивід відформатованого звіту у консоль."""
    if not results:
        logger.warning("Немає даних для відображення звіту.")
        return

    print("\n=== Certificate Expiry & Safety Status ===")
    print(f"{'Domain':<28} {'Issuer':<15} {'Days Left':<10} {'Status':<10} {'Signature Alg'}")
    print("-" * 75)

    expired_count = 0
    warning_count = 0
    issuers = []

    for c in results:
        issuers.append(c.issuer)
        days_str = f"{c.days_left} days"
        print(f"{c.domain:<28} {c.issuer:<15} {days_str:<10} {c.status:<10} {c.signature_alg}")
        if c.status == "EXPIRED":
            expired_count += 1
        elif c.status == "WARNING":
            warning_count += 1

    print("\n=== Issuer Statistics ===")
    issuer_counts = Counter(issuers)
    for issuer, count in issuer_counts.items():
        print(f"{issuer:<15} : {count}")

    if expired_count > 0 or warning_count > 0:
        logger.warning(
            f"{expired_count} certificate(s) EXPIRED! {warning_count} certificate(s) expiring within {days_warning} days!"
        )


def export_report(results: list[CertStatus], output_file: Path, fmt: str = "json") -> None:
    """Експорт результатів аналізу у CSV або JSON з обробкою винятків."""
    try:
        output_file.parent.mkdir(parents=True, exist_ok=True)

        if fmt.lower() == "csv" or output_file.suffix.lower() == ".csv":
            with open(output_file, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow([
                    "Domain",
                    "Issuer",
                    "DaysLeft",
                    "Status",
                    "SignatureAlg",
                    "IsWeakAlg",
                ])
                for c in results:
                    writer.writerow([
                        c.domain,
                        c.issuer,
                        c.days_left,
                        c.status,
                        c.signature_alg,
                        c.is_weak_alg,
                    ])
        else:
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump([c.__dict__ for c in results], f, indent=2, ensure_ascii=False)

        logger.info(f"Report saved to {output_file}")

    except PermissionError:
        logger.error(f"[Помилка доступу] Немає прав для запису у файл: {output_file}")
    except OSError as e:
        logger.error(f"[Помилка вводу/виводу] Не вдалося зберегти звіт у '{output_file}': {e}")
    except Exception as e:  # noqa: BLE001
        logger.error(f"[Несподівана помилка] Помилка під час експорту звіту: {e}")


def run_analysis(
    certs_data: str, days_warning: int = 30, output_report: str | None = None, fmt: str = "json"
) -> None:
    """Головна функція-контролер для запуску аналізу з CLI."""
    certs_path = Path(certs_data)
    results = analyze_certificates(certs_path, days_warning)

    if results:
        print_report(results, days_warning)
        if output_report:
            export_report(results, Path(output_report), fmt)