import asyncio
import sys
from pathlib import Path

from core.config import Config
from core.logger import configure_logging, get_logger
from core.models import ScanResult
from output.writer import write_all
from stages import recon, hunt, api_hack, secrets as secrets_stage, report as report_stage

logger = get_logger("main")


async def run_scan(target: str, config: Config) -> ScanResult:
    logger.info("scan starting target=%s", target)

    result = await recon.run(target)

    if result.subdomains or result.alive_hosts:
        hunt_findings = await hunt.run(result.urls)
        result.findings.extend(hunt_findings)

        api_findings = await api_hack.run(result.alive_hosts, result.urls)
        result.findings.extend(api_findings)

        secrets = await secrets_stage.run(result.alive_hosts, result.urls)
        result.secrets.extend(secrets)

    report = await report_stage.run(result)
    write_all(report, config.scan.output_dir)

    logger.info(
        "scan complete target=%s findings=%d secrets=%d output=%s",
        target, len(result.findings), len(result.secrets), config.scan.output_dir,
    )
    return result


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(
        description="Bug Bounty Recon & Vulnerability Hunting Framework"
    )
    parser.add_argument("target", help="Target domain (e.g. example.com)")
    parser.add_argument("--authorized", action="store_true", required=True,
                        help="Acknowledge target is authorized for testing")
    parser.add_argument("--quick", action="store_true",
                        help="Quick critical-only scan")
    parser.add_argument("--output", type=Path, default=Path("output"),
                        help="Output directory for reports")
    parser.add_argument("--log-file", type=Path, default=Path("scan.log"),
                        help="Log file path")
    parser.add_argument("--log-level", default="INFO",
                        choices=["DEBUG", "INFO", "WARNING", "ERROR"])

    args = parser.parse_args()

    if not args.authorized:
        logger.error("--authorized flag is required")
        sys.exit(2)

    configure_logging(args.log_file, args.log_level)

    config = Config()
    config.scan.target = args.target
    config.scan.authorized = True
    config.scan.quick = args.quick
    config.scan.output_dir = args.output

    result = asyncio.run(run_scan(args.target, config))
    logger.info(
        "Scan result: %d findings, %d secrets",
        len(result.findings), len(result.secrets),
    )


if __name__ == "__main__":
    main()
