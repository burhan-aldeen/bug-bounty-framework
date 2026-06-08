import asyncio
import sys
from pathlib import Path
from urllib.parse import urlparse

from core import checkpoint
from core.config import Config
from core.logger import configure_logging, get_logger
from core.models import AliveHost, ScanResult, Subdomain
from core.runner import anew_merge
from output.writer import write_all, SENSITIVE_PATHS
from stages import recon, hunt, secrets as secrets_stage, report as report_stage

logger = get_logger("main")


_TWO_PART_TLDS = frozenset({
    "com.sa", "com.kw", "com.tr", "com.ae", "com.eg", "com.qa", "com.om",
    "com.bh", "com.lb", "com.jo", "com.pk", "com.bd", "com.lk", "com.np",
    "co.uk", "co.jp", "co.kr", "co.nz", "co.in", "co.za", "co.il",
    "com.cn", "net.cn", "org.cn", "com.hk", "com.tw", "com.mx",
    "com.ar", "com.br", "com.au", "com.sg", "com.my", "com.ph",
    "org.uk", "ac.uk", "gov.uk", "net.uk",
    "org.sa", "net.sa", "gov.sa",
})


def _extract_root(domain: str) -> str:
    parts = domain.strip().lower().split(".")
    if len(parts) < 2:
        return domain
    if len(parts) >= 3 and ".".join(parts[-2:]) in _TWO_PART_TLDS:
        return ".".join(parts[-3:])
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return domain


def _extract_host(url: str) -> str:
    host = urlparse(url).hostname
    return host if host else url


async def run_scan_list(
    targets_file: Path | None,
    config: Config,
    fresh: bool = False,
    subs_list: Path | None = None,
) -> list[ScanResult]:
    # Determine targets
    if subs_list and not targets_file:
        raw = Path(subs_list).read_text(encoding="utf-8-sig").strip().splitlines()
        raw = [s.strip().lower() for s in raw if s.strip()]
        targets = sorted(set(_extract_root(s) for s in raw if s.count(".") >= 1))
        if not targets:
            targets = raw
        logger.info("extracted %d root targets from %s", len(targets), subs_list)
    elif targets_file:
        try:
            lines = targets_file.read_text(encoding="utf-8-sig").strip().splitlines()
        except OSError as exc:
            logger.error("cannot read targets file %s: %s", targets_file, exc)
            return []
        targets = [line.strip() for line in lines if line.strip() and not line.strip().startswith("#")]
        logger.info("scan list: %d targets from %s", len(targets), targets_file)
    else:
        logger.error("no targets specified")
        return []

    cp_dir = config.scan.output_dir
    last_phase = checkpoint.completed_phase(cp_dir)

    if fresh or last_phase == 0:
        if last_phase > 0:
            logger.info("--fresh: clearing checkpoints")
            checkpoint.clear(cp_dir)
        resume = False
    else:
        resume = True
        logger.info("auto-resume from phase %d checkpoint", last_phase)

    # ----------------------------------------------------------------
    # Phase 1a: Subdomain Enumeration (ALL targets)
    # ----------------------------------------------------------------
    if resume and last_phase >= 1:
        raw = checkpoint.load_phase(cp_dir, 1, "1a_subdomains")
        all_subdomain_sets = checkpoint.rebuild_subdomains(raw) if raw else []
        if not all_subdomain_sets:
            logger.warning("checkpoint 1a corrupt, re-running")
            resume = False
    if not resume or last_phase < 1:
        logger.info("=== PHASE 1a: SUBDOMAIN ENUMERATION (%d targets) ===", len(targets))
        all_subdomain_sets: list[list[Subdomain]] = []

        if subs_list:
            raw_subs = Path(subs_list).read_text(encoding="utf-8-sig").strip().splitlines()
            raw_subs = [s.strip().lower() for s in raw_subs if s.strip()]
            for target in targets:
                target_subs = [
                    Subdomain(domain=s, source="user_list")
                    for s in raw_subs if s.endswith(f".{target}") or s == target
                ]
                if not target_subs:
                    target_subs = [
                        Subdomain(domain=s, source="user_list")
                        for s in raw_subs if target in s
                    ]
                all_subdomain_sets.append(target_subs)
            logger.info("loaded %d subdomains from %s", len(raw_subs), subs_list)
        else:
            # 4 subdomain sources merged with anew logic
            all_seen: set[str] = set()
            for i, target in enumerate(targets, 1):
                logger.info("enum [%d/%d]: %s", i, len(targets), target)
                subs = await recon.enumerate_subdomains(target)
                # anew merge
                merged: list[Subdomain] = []
                for s in subs:
                    if s.domain not in all_seen:
                        all_seen.add(s.domain)
                        merged.append(s)
                all_subdomain_sets.append(merged)

        # Save unique list
        all_unique = sorted(set(s.domain for subs in all_subdomain_sets for s in subs))
        output_dir = config.scan.output_dir
        output_dir.mkdir(parents=True, exist_ok=True)
        found_path = output_dir / "found_list.txt"
        found_path.write_text("\n".join(all_unique), encoding="utf-8")
        logger.info("saved %d unique subdomains to %s", len(all_unique), found_path)

        checkpoint.save_phase(cp_dir, 1, "1a_subdomains", all_subdomain_sets)

    # ----------------------------------------------------------------
    # Phase 1b: Alive Check (ALL subdomains)
    # ----------------------------------------------------------------
    if resume and last_phase >= 2:
        raw = checkpoint.load_phase(cp_dir, 2, "1b_alive")
        all_alive = checkpoint.rebuild_alive(raw) if raw else []
        if not all_alive:
            logger.warning("checkpoint 1b corrupt, re-running")
            resume = False
    if not resume or last_phase < 2:
        all_domains: list[str] = []
        for subs in all_subdomain_sets:
            for s in subs:
                all_domains.append(s.domain)
        if not all_domains:
            logger.warning("no subdomains, using root domains as fallback")
            all_domains = targets
        logger.info("=== PHASE 1b: ALIVE CHECK (%d hosts) ===", len(all_domains))
        all_alive = await recon.check_alive(
            list(dict.fromkeys(all_domains)),
            output_dir=config.scan.output_dir,
        )
        # Save alive urls
        alive_urls_path = config.scan.output_dir / "alive_urls.txt"
        alive_urls_path.write_text(
            "\n".join(h.url for h in all_alive if h.url),
            encoding="utf-8",
        )
        logger.info("saved %d alive URLs to %s", len(all_alive), alive_urls_path)
        checkpoint.save_phase(cp_dir, 2, "1b_alive", all_alive)

    # ----------------------------------------------------------------
    # Phase 1c: URL Collection (per target)
    # ----------------------------------------------------------------
    if resume and last_phase >= 3:
        raw_urls = checkpoint.load_phase(cp_dir, 3, "1c_urls")
        all_urls = raw_urls if raw_urls else []
        raw_hosts = checkpoint.load_phase(cp_dir, 3, "1c_hosts")
        all_hosts = checkpoint.rebuild_alive(raw_hosts) if raw_hosts else []
        if not all_urls and not all_hosts:
            logger.warning("checkpoint 1c empty")
    if not resume or last_phase < 3:
        logger.info("=== PHASE 1c: URL COLLECTION (%d targets) ===", len(targets))
        all_urls: list[str] = []
        seen_urls: set[str] = set()
        for i, target in enumerate(targets):
            host_urls = [
                h for h in all_alive
                if target == _extract_root(_extract_host(h.url))
            ]
            if not host_urls:
                logger.info("no alive hosts matched for %s, skipping", target)
                continue
            logger.info("target %s: %d alive hosts", target, len(host_urls))
            urls = await recon.collect_urls(target, host_urls)
            for u in urls:
                if u not in seen_urls:
                    seen_urls.add(u)
                    all_urls.append(u)
        all_hosts: list[AliveHost] = list({h.url: h for h in all_alive}.values())

        # Save all URLs
        if all_urls:
            urls_path = config.scan.output_dir / "all_urls.txt"
            urls_path.write_text("\n".join(all_urls), encoding="utf-8")
            logger.info("saved %d URLs to %s", len(all_urls), urls_path)

        checkpoint.save_phase(cp_dir, 3, "1c_urls", all_urls)
        checkpoint.save_phase(cp_dir, 3, "1c_hosts", all_hosts)

    # Build per-target ScanResult objects
    all_results: list[ScanResult] = []
    for i, target in enumerate(targets):
        result = ScanResult(target=target)
        result.subdomains = all_subdomain_sets[i] if i < len(all_subdomain_sets) else []
        result.alive_hosts = [
            h for h in all_alive
            if target == _extract_root(_extract_host(h.url))
        ]
        result.urls = [
            u for u in all_urls
            if target == _extract_root(_extract_host(u))
        ]
        all_results.append(result)

    # ----------------------------------------------------------------
    # Phase 2a-2e: HUNT (ALL urls)
    # ----------------------------------------------------------------
    if resume and last_phase >= 4:
        raw = checkpoint.load_phase(cp_dir, 4, "2_hunt")
        all_hunt_findings = checkpoint.rebuild_findings(raw) if raw else []
    else:
        logger.info("=== PHASE 2: HUNT (%d urls) ===", len(all_urls))
        alive_urls_list = [h.url for h in all_alive if h.url]
        all_hunt_findings = await hunt.run(all_urls, alive_urls_list)
        checkpoint.save_phase(cp_dir, 4, "2_hunt", all_hunt_findings)

    # ----------------------------------------------------------------
    # Phase 3+4: SECRETS (ALL hosts + urls)
    # ----------------------------------------------------------------
    if resume and last_phase >= 5:
        raw = checkpoint.load_phase(cp_dir, 5, "3_secrets")
        all_secrets = checkpoint.rebuild_secrets(raw) if raw else []
    else:
        logger.info("=== PHASE 3+4: SECRETS (%d hosts) ===", len(all_hosts))
        all_secrets = await secrets_stage.run(
            all_hosts, all_urls, output_dir=config.scan.output_dir
        )
        checkpoint.save_phase(cp_dir, 5, "3_secrets", all_secrets)

    # ----------------------------------------------------------------
    # Phase 5: REPORT (distribute findings + generate reports)
    # ----------------------------------------------------------------
    logger.info("=== PHASE 5: REPORT ===")
    base_output_dir = config.scan.output_dir
    for i, result in enumerate(all_results):
        config.scan.target = targets[i]
        output_dir = base_output_dir / targets[i].replace(".", "_")
        config.scan.output_dir = output_dir

        tgt = targets[i]
        result.findings = [
            f for f in all_hunt_findings
            if f.url and tgt == _extract_root(_extract_host(f.url))
        ]
        result.secrets = [
            s for s in all_secrets
            if s.url and tgt == _extract_root(_extract_host(s.url))
        ]

        report = await report_stage.run(result, config=config)
        write_all(report, output_dir)

        logger.info(
            "scan list [%d/%d] %s done: findings=%d secrets=%d",
            i + 1, len(targets), targets[i],
            len(result.findings), len(result.secrets),
        )

    logger.info("=== ALL PHASES COMPLETE (%d targets) ===", len(targets))
    return all_results


async def run_scan(target: str, config: Config) -> ScanResult:
    logger.info("scan starting target=%s", target)
    result = ScanResult(target=target)

    # Phase 1a
    result.subdomains = await recon.enumerate_subdomains(target)

    # Phase 1b
    domains = [s.domain for s in result.subdomains] or [target]
    result.alive_hosts = await recon.check_alive(
        list(dict.fromkeys(domains)),
        output_dir=config.scan.output_dir,
    )

    # Phase 1c
    result.urls = await recon.collect_urls(target, result.alive_hosts)

    # Phase 2
    alive_urls = [h.url for h in result.alive_hosts if h.url]
    result.findings = await hunt.run(result.urls, alive_urls)

    # Phase 3+4
    result.secrets = await secrets_stage.run(
        result.alive_hosts, result.urls, output_dir=config.scan.output_dir
    )

    # Phase 5
    report = await report_stage.run(result, config=config)
    write_all(report, config.scan.output_dir)

    logger.info(
        "scan complete target=%s findings=%d secrets=%d",
        target, len(result.findings), len(result.secrets),
    )
    return result


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
                        help="Output directory")
    parser.add_argument("--log-file", type=Path, default=Path("scan.log"),
                        help="Log file path")
    parser.add_argument("--log-level", default="INFO",
                        choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    parser.add_argument("--fresh", action="store_true",
                        help="Ignore checkpoints and start fresh")
    parser.add_argument("--subs-list", type=Path, dest="subs_list",
                        help="Skip enumeration, load subdomains from file")

    args = parser.parse_args()

    if not args.authorized:
        logger.error("--authorized flag is required")
        sys.exit(2)

    if not args.target and not args.targets_file and not args.subs_list:
        logger.error("provide a target, --list, or --subs-list")
        sys.exit(2)

    configure_logging(args.log_file, args.log_level)

    config = Config()
    config.scan.authorized = True
    config.scan.quick = args.quick
    config.scan.output_dir = args.output

    if args.targets_file or args.subs_list:
        results = asyncio.run(
            run_scan_list(args.targets_file, config, fresh=args.fresh, subs_list=args.subs_list)
        )
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
