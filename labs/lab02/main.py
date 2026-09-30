import argparse
import sys

from labs.lab02.task1 import run_demo
from labs.lab02.task2 import run_analysis


def main():
    parser = argparse.ArgumentParser(
        description="Лабораторна робота №2 — Cybersecurity CLI Tools"
    )
    subparsers = parser.add_subparsers(dest="command", help="Команда для виконання")

    # Підкоманда demo (Завдання 1)
    subparsers.add_parser("demo", help="Запустити демонстрацію класів ООП")

    # Підкоманда analyze (Завдання 2)
    analyze_parser = subparsers.add_parser(
        "analyze", help="Запустити аналіз SSL-сертифікатів"
    )
    analyze_parser.add_argument(
        "--certs-data",
        type=str,
        default="labs/lab02/data/certificates.json",
        help="Шлях до файлу certificates.json",
    )
    analyze_parser.add_argument(
        "--days-warning",
        type=int,
        default=30,
        help="Поріг попередження про закінчення терміну (у днях)",
    )
    analyze_parser.add_argument(
        "--output-report",
        type=str,
        default="labs/lab02/data/ssl_expiry_report.csv",
        help="Шлях для збереження звіту",
    )
    analyze_parser.add_argument(
        "--format",
        type=str,
        choices=["json", "csv"],
        default="csv",
        help="Формат звіту (json або csv)",
    )

    args = parser.parse_args()

    if args.command == "demo":
        run_demo()
    elif args.command == "analyze":
        run_analysis(
            args.certs_data, args.days_warning, args.output_report, args.format
        )
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
