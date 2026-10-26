"""WSL/Linux side counterpart of Get-AuditSummary (Test-Emudhra.Helpers.ps1).

No network access, no installation. Standard library only.

  rows <python-path> <target-label>   : read probe_python.py JSON on stdin, emit TSV rows
  summary <tsv> <control> <t1> [<t2>] : per tool, FIXED only if exactly one ACCEPT control row
                                        and exactly one REJECT row per distinct target;
                                        VULNERABLE if a target ACCEPTs and the single control row
                                        is ACCEPT or UNKNOWN (v2.11.5)
TSV columns: tool, target, verdict, detail. Verdict is exactly ACCEPT / REJECT / UNKNOWN / NONE.
"""
import json
import sys
from collections import defaultdict

VERDICTS = {'ACCEPT', 'REJECT', 'UNKNOWN', 'NONE'}
ROUTES = ('stdlib-ssl', 'certifi', 'requests')


def clean(text):
    return str(text).replace('\t', ' ').replace('\r', ' ').replace('\n', ' ')[:200]


def emit_rows(python, target, raw):
    """Malformed or missing probe output becomes UNKNOWN for every route, never dropped."""
    try:
        data = json.loads(raw)
        found = {}
        for item in data:
            if item.get('route') in ROUTES and item.get('verdict') in VERDICTS:
                if item['route'] in found:
                    raise ValueError('duplicate route')
                found[item['route']] = item
        if set(found) != set(ROUTES):
            raise ValueError('route missing')
    except Exception as error:  # noqa: BLE001 - any failure is UNKNOWN
        found = {r: {'verdict': 'UNKNOWN', 'detail': 'probe failed: ' + type(error).__name__} for r in ROUTES}
    out = []
    for route in ROUTES:
        item = found[route]
        out.append('\t'.join([clean('py:%s/%s' % (python, route)), clean(target),
                              item['verdict'], clean(item.get('detail', ''))]))
    return out


def summarize(rows, control, targets):
    if len(set(targets)) != len(targets):
        raise SystemExit('Targets must be unique.')
    groups = defaultdict(list)
    for tool, target, verdict, _detail in rows:
        groups[tool].append((target, verdict))
    result = []
    for tool in sorted(groups):
        items = groups[tool]
        if items and all(v == 'NONE' for _t, v in items):
            result.append((tool, 'N/A', 'Module not installed (not counted as FIXED).'))
            continue
        ctrl = [v for t, v in items if t == control]
        status, reason = 'UNKNOWN', 'Control missing, duplicated, or not ACCEPT.'
        # v2.11.5: an accepted target is a completed handshake on its own, so a single UNKNOWN control
        # (old uv cannot prove the control request) still gives VULNERABLE. FIXED always needs an ACCEPT control.
        if ctrl in (['ACCEPT'], ['UNKNOWN']):
            ctrl_ok = ctrl == ['ACCEPT']
            per_target = []
            complete = True
            for target in targets:
                matches = [v for t, v in items if t == target]
                if len(matches) != 1:
                    complete = False
                else:
                    per_target.append(matches[0])
            if not complete:
                if ctrl_ok:
                    reason = 'Target missing or duplicated.'
            elif 'ACCEPT' in per_target:
                status = 'VULNERABLE'
                reason = 'At least one target accepted.' if ctrl_ok else 'At least one target accepted (control UNKNOWN).'
            elif not ctrl_ok:
                pass  # control UNKNOWN and no target accepted: the control reason stays
            elif per_target.count('REJECT') == len(targets):
                status, reason = 'FIXED', 'Every expected target rejected.'
            else:
                reason = 'At least one target UNKNOWN or NONE.'
        result.append((tool, status, reason))
    return result


def read_tsv(path):
    rows = []
    with open(path, encoding='utf-8') as handle:
        for line in handle:
            parts = line.rstrip('\n').split('\t')
            if len(parts) < 3:
                continue
            parts += [''] * (4 - len(parts))
            rows.append(tuple(parts[:4]))
    return rows


def main(argv):
    if len(argv) >= 3 and argv[0] == 'rows':
        for line in emit_rows(argv[1], argv[2], sys.stdin.read()):
            print(line)
        return 0
    if len(argv) >= 4 and argv[0] == 'summary':
        print('tool\tstatus\treason')
        for tool, status, reason in summarize(read_tsv(argv[1]), argv[2], argv[3:]):
            print('%s\t%s\t%s' % (tool, status, reason))
        return 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
