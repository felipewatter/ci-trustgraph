"""Command line interface, with explicit exit statuses for CI gating."""
import argparse
import json
import sys
from pathlib import Path
from .parser import InputError, load_workflows
from .engine import scan
from .model import SEVERITY
from .report import result, render_text, render_sarif, diff


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog='ci-trustgraph', description='Offline GitHub Actions trust-boundary analysis')
    ap.add_argument('root', nargs='?', default='.', help='repository root containing .github/workflows')
    ap.add_argument('--format', choices=['text', 'json', 'sarif'], default='text')
    ap.add_argument('--output', help='write output to file instead of stdout')
    ap.add_argument('--fail-on', choices=['off', 'info', 'low', 'medium', 'high', 'critical'], default='high')
    ap.add_argument('--baseline', help='previous JSON scan report; compare fingerprints')
    ap.add_argument('--graph', help='write the trust graph in JSON')
    args = ap.parse_args(argv)
    try:
        workflows = load_workflows(Path(args.root))
        findings, edges = scan(workflows)
        if args.baseline:
            path = Path(args.baseline)
            if path.is_symlink() or path.stat().st_size > 5 * 1024 * 1024:
                raise InputError('invalid or oversized baseline')
            obj = json.loads(path.read_text(encoding='utf-8'))
            if obj.get('schema_version') != '1.0' or not isinstance(obj.get('findings'), list):
                raise InputError('baseline requires a CI TrustGraph JSON scan report')
            summary = diff(obj['findings'], findings)
        else:
            summary = None
        body = (render_text(findings, edges) if args.format == 'text'
                else json.dumps(render_sarif(findings) if args.format == 'sarif' else result(findings, edges), indent=2, ensure_ascii=False) + '\n')
        if args.output:
            Path(args.output).write_text(body, encoding='utf-8')
        else:
            sys.stdout.write(body)
        if args.graph:
            Path(args.graph).write_text(json.dumps({"edges": [e.to_dict() for e in edges]}, indent=2) + '\n', encoding='utf-8')
        if summary is not None:
            sys.stderr.write('Baseline diff: ' + json.dumps({k: len(v) if isinstance(v, list) else v for k, v in summary.items()}) + '\n')
        relevant = summary['introduced'] if summary is not None else [f.to_dict() for f in findings]
        return 2 if args.fail_on != 'off' and any(SEVERITY[f['severity']] >= SEVERITY[args.fail_on] for f in relevant) else 0
    except (InputError, OSError, ValueError, KeyError, TypeError) as exc:
        sys.stderr.write(f'ci-trustgraph: invalid input: {exc}\n')
        return 3


if __name__ == '__main__':
    raise SystemExit(main())
