import asyncio
import sys
from pathlib import Path

from core.config import Config
from core.logger import configure_logging, get_logger
from core.models import AliveHost, ScanResult, Subdomain
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


async def run_scan_list(targets_file: Path, config: Config) -> list[ScanResult]:
    try:
        lines = targets_file.read_text(encoding="utf-8-sig").strip().splitlines()
    except OSError as exc:
        logger.error("cannot read targets file %s: %s", targets_file, exc)
        return []
    targets = [line.strip() for line in lines if line.strip() and not line.strip().startswith("#")]
    logger.info("scan list: %d targets from %s", len(targets), targets_file)

    # Phase 1a — Subdomain enumeration: ALL targets first
    logger.info("=== PHASE 1a: SUBDOMAIN ENUMERATION (%d targets) ===", len(targets))
    all_subdomain_sets: list[list[Subdomain]] = []
    for i, target in enumerate(targets, 1):
        logger.info("enum [%d/%d]: %s", i, len(targets), target)
        subs = await recon.enumerate_subdomains(target)
        all_subdomain_sets.append(subs)

    # Phase 1b — Alive check: ALL subdomains from ALL targets
    all_domains: list[str] = []
    target_domain_map: dict[str, str] = {}  # subdomain -> original target
    for i, target in enumerate(targets):
        for s in all_subdomain_sets[i]:
            all_domains.append(s.domain)
            target_domain_map[s.domain] = target

    if not all_domains:
        logger.warning("no subdomains found across any target, trying root domains")
        all_domains = targets
        for t in targets:
            target_domain_map[t] = t

    logger.info("=== PHASE 1b: ALIVE CHECK (%d unique hosts) ===", len(all_domains))
    all_alive = await recon.check_alive(list(dict.fromkeys(all_domains)))

    # Phase 1c — URL collection: for ALL targets
    logger.info("=== PHASE 1c: URL COLLECTION (%d targets) ===", len(targets))
    all_urls: list[str] = []
    seen_urls: set[str] = set()
    for i, target in enumerate(targets):
        host_urls = [h for h in all_alive if target_domain_map.get(h.url.split("//")[-1].split("/")[0], "") == target]
        if not host_urls:
            host_urls = [h for h in all_alive]
        urls = await recon.collect_urls(target, host_urls)
        for u in urls:
            if u not in seen_urls:
                seen_urls.add(u)
                all_urls.append(u)

    # Build per-target ScanResult objects
    all_results: list[ScanResult] = []
    for i, target in enumerate(targets):
        result = ScanResult(target=target)
        result.subdomains = all_subdomain_sets[i]
        result.alive_hosts = [h for h in all_alive if target in h.url or target_domain_map.get(h.url.split("//")[-1].split("/")[0], "") == target]
        result.urls = [u for u in all_urls if target in u]
        all_results.append(result)

    # Phase 2 — Hunt on ALL URLs
    logger.info("=== PHASE 2: HUNT (%d urls) ===", len(all_urls))
    all_hunt_findings = await hunt.run(all_urls)

    # Phase 3 — API Hacking on ALL hosts
    logger.info("=== PHASE 3: API HACKING (%d hosts) ===", len(all_hosts))
    all_api_findings = await api_hack.run(all_hosts, all_urls)

    # Phase 4 — Secrets on ALL hosts
    logger.info("=== PHASE 4: SECRETS (%d hosts) ===", len(all_hosts))
    all_secrets = await secrets_stage.run(all_hosts, all_urls)

    # Phase 5 — Distribute findings back to per-target results + report
    logger.info("=== PHASE 5: REPORT ===")
    for i, result in enumerate(all_results):
        config.scan.target = targets[i]
        output_dir = config.scan.output_dir / targets[i].replace(".", "_")
        config.scan.output_dir = output_dir

        result.findings = [f for f in all_hunt_findings if targets[i] in f.url or targets[i] in result.urls]
        result.findings.extend(f for f in all_api_findings if targets[i] in f.url or targets[i] in result.urls)
        result.secrets = [s for s in all_secrets if targets[i] in s.url or targets[i] in result.urls]

        report = await report_stage.run(result)
        write_all(report, output_dir)

        logger.info(
            "scan list [%d/%d] %s done: findings=%d secrets=%d",
            i + 1, len(targets), targets[i],
            len(result.findings), len(result.secrets),
        )

    logger.info("=== ALL PHASES COMPLETE (%d targets) ===", len(targets))
    return all_results


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(
        description="Bug Bounty Recon & Vulnerability Hunting Framework"
    )
    parser.add_argument("target", nargs="?", help="Target domain (e.g. example.com)")
    parser.add_argument("--list", "-l", type=Path, dest="targets_file",
                        help="File with one target domain per line")
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

    if not args.target and not args.targets_file:
        logger.error("provide a target domain or --list file")
        sys.exit(2)

    configure_logging(args.log_file, args.log_level)

    config = Config()
    config.scan.authorized = True
    config.scan.quick = args.quick
    config.scan.output_dir = args.output

    if args.targets_file:
        results = asyncio.run(run_scan_list(args.targets_file, config))
        total_findings = sum(len(r.findings) for r in results)
        total_secrets = sum(len(r.secrets) for r in results)
        logger.info(
            "Scan list complete: %d targets, %d findings, %d secrets",
            len(results), total_findings, total_secrets,
        )
    else:
        config.scan.target = args.target
        result = asyncio.run(run_scan(args.target, config))
        logger.info(
            "Scan result: %d findings, %d secrets",
            len(result.findings), len(result.secrets),
        )


if __name__ == "__main__":
    main()
