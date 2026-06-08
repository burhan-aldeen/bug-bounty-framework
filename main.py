import asyncio
import sys
from pathlib import Path

from core import checkpoint
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


async def run_scan_list(targets_file: Path, config: Config, fresh: bool = False, subs_list: Path | None = None) -> list[ScanResult]:
    try:
        lines = targets_file.read_text(encoding="utf-8-sig").strip().splitlines()
    except OSError as exc:
        logger.error("cannot read targets file %s: %s", targets_file, exc)
        return []
    targets = [line.strip() for line in lines if line.strip() and not line.strip().startswith("#")]
    logger.info("scan list: %d targets from %s", len(targets), targets_file)

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
    # Phase 1a — Subdomain enumeration: ALL targets first
    # ----------------------------------------------------------------
    if resume and last_phase >= 1 and not subs_list:
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
                target_subs = [Subdomain(domain=s, source="user_list") for s in raw_subs if s.endswith(f".{target}") or s == target]
                if not target_subs:
                    target_subs = [Subdomain(domain=s, source="user_list") for s in raw_subs if target in s]
                all_subdomain_sets.append(target_subs)
            logger.info("loaded %d subdomains from %s", len(raw_subs), subs_list)
        else:
            for i, target in enumerate(targets, 1):
                logger.info("enum [%d/%d]: %s", i, len(targets), target)
                subs = await recon.enumerate_subdomains(target)
                all_subdomain_sets.append(subs)

            amass_subs = await recon.run_amass(targets)
            if amass_subs:
                logger.info("distributing %d amass results to targets", len(amass_subs))
                for s in amass_subs:
                    for i, target in enumerate(targets):
                        if s.domain.endswith(f".{target}") or s.domain == target:
                            seen = set(sub.domain for sub in all_subdomain_sets[i])
                            if s.domain not in seen:
                                all_subdomain_sets[i].append(s)
                            break

        all_unique = sorted(set(s.domain for subs in all_subdomain_sets for s in subs))
        output_dir = config.scan.output_dir
        output_dir.mkdir(parents=True, exist_ok=True)
        found_path = output_dir / "found_list.txt"
        found_path.write_text("\n".join(all_unique))
        logger.info("saved %d unique subdomains to %s", len(all_unique), found_path)

        checkpoint.save_phase(cp_dir, 1, "1a_subdomains", all_subdomain_sets)

    # ----------------------------------------------------------------
    # Phase 1b — Alive check: ALL subdomains from ALL targets
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
            logger.warning("no subdomains found, trying root domains")
            all_domains = targets
        logger.info("=== PHASE 1b: ALIVE CHECK (%d unique hosts) ===", len(all_domains))
        all_alive = await recon.check_alive(list(dict.fromkeys(all_domains)))
        checkpoint.save_phase(cp_dir, 2, "1b_alive", all_alive)

    # ----------------------------------------------------------------
    # Phase 1c — URL collection: for ALL targets
    # ----------------------------------------------------------------
    if resume and last_phase >= 3:
        raw_urls = checkpoint.load_phase(cp_dir, 3, "1c_urls")
        all_urls = raw_urls if raw_urls else []
        raw_hosts = checkpoint.load_phase(cp_dir, 3, "1c_hosts")
        all_hosts = checkpoint.rebuild_alive(raw_hosts) if raw_hosts else []
        if not all_urls and not all_hosts:
            logger.warning("checkpoint 1c corrupt, re-running")
            resume = False
    if not resume or last_phase < 3:
        logger.info("=== PHASE 1c: URL COLLECTION (%d targets) ===", len(targets))
        all_urls: list[str] = []
        seen_urls: set[str] = set()
        for i, target in enumerate(targets):
            host_urls = [h for h in all_alive if target in h.url]
            if not host_urls:
                host_urls = all_alive
            urls = await recon.collect_urls(target, host_urls)
            for u in urls:
                if u not in seen_urls:
                    seen_urls.add(u)
                    all_urls.append(u)
        all_hosts: list[AliveHost] = list({h.url: h for h in all_alive}.values())
        checkpoint.save_phase(cp_dir, 3, "1c_urls", all_urls)
        checkpoint.save_phase(cp_dir, 3, "1c_hosts", all_hosts)

    # Build per-target ScanResult objects
    all_results: list[ScanResult] = []
    for i, target in enumerate(targets):
        result = ScanResult(target=target)
        result.subdomains = all_subdomain_sets[i]
        result.alive_hosts = [h for h in all_alive if target in h.url]
        result.urls = [u for u in all_urls if target in u]
        all_results.append(result)

    # ----------------------------------------------------------------
    # Phase 2 — Hunt on ALL URLs
    # ----------------------------------------------------------------
    if resume and last_phase >= 4:
        raw = checkpoint.load_phase(cp_dir, 4, "2_hunt")
        all_hunt_findings = checkpoint.rebuild_findings(raw) if raw else []
        if not all_hunt_findings and all_urls:
            logger.warning("checkpoint 2 empty but urls exist, re-running")
            resume = False
    if not resume or last_phase < 4:
        logger.info("=== PHASE 2: HUNT (%d urls) ===", len(all_urls))
        all_hunt_findings = await hunt.run(all_urls)
        checkpoint.save_phase(cp_dir, 4, "2_hunt", all_hunt_findings)

    # ----------------------------------------------------------------
    # Phase 3 — API Hacking on ALL hosts
    # ----------------------------------------------------------------
    if resume and last_phase >= 5:
        raw = checkpoint.load_phase(cp_dir, 5, "3_api")
        all_api_findings = checkpoint.rebuild_findings(raw) if raw else []
    else:
        logger.info("=== PHASE 3: API HACKING (%d hosts) ===", len(all_hosts))
        all_api_findings = await api_hack.run(all_hosts, all_urls)
        checkpoint.save_phase(cp_dir, 5, "3_api", all_api_findings)

    # ----------------------------------------------------------------
    # Phase 4 — Secrets on ALL hosts
    # ----------------------------------------------------------------
    if resume and last_phase >= 6:
        raw = checkpoint.load_phase(cp_dir, 6, "4_secrets")
        all_secrets = checkpoint.rebuild_secrets(raw) if raw else []
    else:
        logger.info("=== PHASE 4: SECRETS (%d hosts) ===", len(all_hosts))
        all_secrets = await secrets_stage.run(all_hosts, all_urls)
        checkpoint.save_phase(cp_dir, 6, "4_secrets", all_secrets)

    # ----------------------------------------------------------------
    # Phase 5 — Distribute findings + report
    # ----------------------------------------------------------------
    logger.info("=== PHASE 5: REPORT ===")
    base_output_dir = config.scan.output_dir
    for i, result in enumerate(all_results):
        config.scan.target = targets[i]
        output_dir = base_output_dir / targets[i].replace(".", "_")
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
    parser.add_argument("--fresh", action="store_true",
                        help="Ignore checkpoints and start fresh")
    parser.add_argument("--subs-list", type=Path, dest="subs_list",
                        help="Skip enumeration, load subdomains from file")

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
        results = asyncio.run(run_scan_list(args.targets_file, config, fresh=args.fresh, subs_list=args.subs_list))
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
