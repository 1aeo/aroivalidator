#!/usr/bin/env python3
"""
AROI Validator CLI — Dispatcher

Modes:
  interactive   Web UI with parallel validation controls (default)
  batch         Automated parallel batch processing (writes JSON)
  viewer        View saved validation results in web UI
  insights      Render human-readable ciissversion:2 → ciissversion:3
                migration summary from a saved results JSON

Flags:
  --ciiss-versions <list>   Comma-separated CIISS versions to validate
                            (default: 2,3). Affects interactive/batch modes.

Environment (batch mode):
  BATCH_LIMIT       Max relays to validate (default: 100)
  PARALLEL          Use parallel processing (default: true)
  MAX_WORKERS       Number of worker threads (default: 10)
  CIISS_VERSIONS    Fallback for --ciiss-versions when flag absent.
"""
import sys
import subprocess
import argparse


def _build_parser():
    parser = argparse.ArgumentParser(
        description="AROI Validator with multi-ciissversion + parallel processing support",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python aroi_cli.py                                    # Interactive (web UI)
  python aroi_cli.py batch                              # Batch with defaults
  python aroi_cli.py batch --ciiss-versions 2,3        # Validate both versions
  python aroi_cli.py batch --ciiss-versions 3          # Only ciissversion:3
  python aroi_cli.py insights                          # Render migration summary
  python aroi_cli.py insights validation_results/aroi_validation_*.json

  BATCH_LIMIT=500 MAX_WORKERS=20 python aroi_cli.py batch
  CIISS_VERSIONS=2 python aroi_cli.py batch            # env-var fallback
""",
    )

    parser.add_argument(
        'mode',
        nargs='?',
        default='interactive',
        choices=['interactive', 'batch', 'viewer', 'insights'],
        help='Operational mode',
    )

    parser.add_argument(
        '--ciiss-versions',
        dest='ciiss_versions',
        default=None,
        help='Comma-separated CIISS versions to validate (default: 2,3). '
             'Falls back to CIISS_VERSIONS env var if unset.',
    )

    parser.add_argument(
        'insights_file',
        nargs='?',
        default=None,
        help="(insights mode only) Path to results JSON. Defaults to "
             "validation_results/latest.json.",
    )

    return parser


def _run_insights(insights_file):
    """Render human-readable migration insights from a saved results JSON."""
    import json
    from pathlib import Path
    from aroi_validator import format_migration_insights, load_results

    if insights_file:
        path = Path(insights_file)
        if not path.exists():
            print(f"error: file not found: {insights_file}", file=sys.stderr)
            return 1
        try:
            data = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError) as e:
            print(f"error: cannot read {insights_file}: {e}", file=sys.stderr)
            return 1
    else:
        data = load_results('latest.json')
        if data is None:
            print(
                "error: no saved results found at validation_results/latest.json. "
                "Run a batch validation first, or pass an explicit file path.",
                file=sys.stderr,
            )
            return 1

    stats = data.get('statistics') or {}
    results = data.get('results') or []
    print(format_migration_insights(stats, results))
    return 0


def _validate_versions_flag(value):
    """Validate --ciiss-versions early so we fail fast with a clean message."""
    from aroi_validator import parse_ciissversions_flag
    try:
        return parse_ciissversions_flag(value)
    except ValueError as e:
        print(f"error: --ciiss-versions: {e}", file=sys.stderr)
        sys.exit(2)


def main():
    parser = _build_parser()
    args = parser.parse_args()

    if args.mode == 'insights':
        sys.exit(_run_insights(args.insights_file))

    # For interactive/batch/viewer, validate the flag early if provided.
    # The actual versions tuple is passed as a string through to app.py;
    # app.py re-parses (with env-var fallback) for use by the validator.
    if args.ciiss_versions is not None:
        _validate_versions_flag(args.ciiss_versions)

    forwarded_args = []
    if args.ciiss_versions is not None:
        forwarded_args += ['--ciiss-versions', args.ciiss_versions]

    if args.mode == 'batch':
        subprocess.run([sys.executable, "app.py", "--mode", "batch", *forwarded_args])
        return

    # interactive / viewer → Streamlit
    print(f"Starting AROI Validator - {args.mode.capitalize()} Mode")
    print("=" * 50)
    print("Opening web interface on port 5000...")

    cmd = [
        sys.executable, "-m", "streamlit", "run",
        "app.py",
        "--server.port", "5000",
        "--server.address", "0.0.0.0",
        "--server.headless", "true",
        "--", "--mode", args.mode, *forwarded_args,
    ]

    try:
        subprocess.run(cmd)
    except KeyboardInterrupt:
        print("\nShutting down...")
        sys.exit(0)


if __name__ == "__main__":
    main()
