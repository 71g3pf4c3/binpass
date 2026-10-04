#!/usr/bin/env bash
# Fail when the two CI definitions drift apart.
#
# CI exists twice — .github/workflows/ci.yml and .gitlab-ci.yml — and was
# synced by hand, so a check added to one quietly never reached the other.
# This extracts the comparable surface from both (every go build/test/lint
# command plus the fuzz/security/docker/nix/release checks), normalizes the
# syntactic differences between the two dialects — GitHub matrix expansion
# vs per-job GOOS=/GOARCH= prefixes, action args vs script lines, -o output
# paths — and diffs the result.
#
# Checks that legitimately exist on one side only are named in PLATFORM_ONLY
# below. A new one-sided check fails until it is either mirrored or added
# there with a reason, which is the point: drift must be a decision, not an
# accident.
#
# Usage: scripts/ci-parity.sh [--verbose]
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# python3 (stdlib only, no PyYAML) because hand-parsing YAML in sh is how
# the checker itself starts to drift. The mini-parser below models exactly
# the constructs these two files use and raises on anything else.
exec python3 - "$repo_root" "$@" <<'PY'
import json
import os
import re
import shlex
import sys
from itertools import product

GITHUB_CI = '.github/workflows/ci.yml'
GITLAB_CI = '.gitlab-ci.yml'

# Checks that are allowed to exist on one CI only. Keep every entry
# commented: the reason is the contract, not the name.
PLATFORM_ONLY = {
    # The GitHub runner has Docker, privileged containers and Nix; the
    # GitLab runners this project uses do not.
    'fuzz',
    'security/govulncheck',
    'docker/Dockerfile.test',
    'docker/Dockerfile.ss',
    'docker/Dockerfile.luks',
    'nix/flake-check',
    'nix/devshell-test',
    # gofmt is currently a GitLab-only job; neither golangci-lint config
    # runs a formatter, so without this entry the check would be lost.
    'lint/gofmt',
    # Releases are cut by tag pipelines on GitLab; ci.yml has no release job.
    'release/goreleaser',
}

# Extraction sanity anchors. If one of these disappears from BOTH sides
# the mini-parser has probably stopped seeing the file, so the script
# errors instead of comparing two empty inventories.
REQUIRED = {
    'lint/vet',
    'lint/golangci-lint',
    'test/race',
    'test/coverage',
    'test/coverage-filter',
    'test/coverage-gate',
}


class ParseError(Exception):
    """The mini-YAML reader hit syntax it does not model."""


# ---------------------------------------------------------------------------
# Mini-YAML: block mappings, block sequences, flow lists, literal blocks,
# anchors and merge keys (tolerated, not resolved). Nothing else.

def _indent(line):
    return len(line) - len(line.lstrip(' '))


def _significant(lines, i):
    """Index of the next non-blank, non-comment line at or after i."""
    while i < len(lines):
        s = lines[i].strip()
        if s and not s.startswith('#'):
            return i
        i += 1
    return None


def _unquote(s):
    if len(s) >= 2 and s[0] == s[-1] and s[0] in '"\'':
        return s[1:-1]
    return s


def _scalar(tok):
    tok = tok.strip()
    if tok.startswith('[') and tok.endswith(']'):
        inner = tok[1:-1].strip()
        if not inner:
            return []
        return [_unquote(p.strip()) for p in inner.split(',')]
    return _unquote(tok)


_KEY_RE = re.compile(r'^([^:]+):(?:\s+(.*))?$')
# A sequence item only opens a mapping when the text before the colon
# looks like a key; shell lines such as `command -v pass || { echo "x: y"; }`
# contain colons but never match.
_MAP_ITEM_RE = re.compile(r'^(?:<<|[A-Za-z_][A-Za-z0-9_.-]*):(?:\s|$)')


def _parse_literal(lines, i, parent_indent):
    block = []
    j = i
    while j < len(lines):
        line = lines[j]
        if not line.strip():
            block.append('')
            j += 1
        elif _indent(line) > parent_indent:
            block.append(line)
            j += 1
        else:
            break
    while block and not block[-1].strip():
        block.pop()
    if not block:
        raise ParseError('empty literal block at line %d' % (i + 1))
    base = min(_indent(l) for l in block if l.strip())
    return '\n'.join(l[base:] if l.strip() else '' for l in block), j


def _parse_map(lines, i, indent, seed=None):
    out = {}
    j = i
    pending = [seed] if seed else []
    while True:
        if pending:
            key, rest = pending.pop(0)
        else:
            k = _significant(lines, j)
            if k is None:
                break
            line = lines[k]
            cur = _indent(line)
            if cur < indent:
                break
            if cur > indent:
                raise ParseError('line %d: unexpected indentation' % (k + 1))
            text = line.strip()
            if text == '-' or text.startswith('- '):
                raise ParseError('line %d: sequence item inside mapping' % (k + 1))
            m = _KEY_RE.match(text)
            if not m:
                raise ParseError('line %d: not a mapping entry: %r' % (k + 1, text))
            key = _unquote(m.group(1))
            rest = (m.group(2) or '').strip()
            j = k + 1
        if rest.startswith('&'):
            parts = rest.split(None, 1)
            rest = parts[1].strip() if len(parts) > 1 else ''
        if rest in ('|', '|-', '|+'):
            val, j = _parse_literal(lines, j, indent)
        elif rest == '':
            k = _significant(lines, j)
            if k is not None and _indent(lines[k]) > indent:
                val, j = _parse_node(lines, k, _indent(lines[k]))
            else:
                val = None
        else:
            # Aliases stay as '*name' strings: every anchored key in these
            # files is either hidden or merged via '<<', which the
            # extractors skip.
            val = _scalar(rest)
        out[key] = val
    return out, j


def _parse_seq(lines, i, indent):
    out = []
    j = i
    while True:
        k = _significant(lines, j)
        if k is None:
            break
        line = lines[k]
        cur = _indent(line)
        if cur < indent:
            break
        if cur > indent:
            raise ParseError('line %d: unexpected indentation in sequence' % (k + 1))
        rest = line[cur:]
        if rest == '-':
            n = _significant(lines, k + 1)
            if n is None or _indent(lines[n]) <= indent:
                out.append(None)
                j = k + 1
                continue
            val, j = _parse_node(lines, n, _indent(lines[n]))
            out.append(val)
            continue
        if not rest.startswith('- '):
            raise ParseError('line %d: expected sequence item, got %r' % (k + 1, rest))
        content = rest[2:]
        if content in ('|', '|-', '|+'):
            val, j = _parse_literal(lines, k + 1, cur)
            out.append(val)
            continue
        if _MAP_ITEM_RE.match(content):
            m = _KEY_RE.match(content)
            key = _unquote(m.group(1))
            restv = (m.group(2) or '').strip()
            val, j = _parse_map(lines, k + 1, cur + 2, seed=(key, restv))
            out.append(val)
            continue
        out.append(_scalar(content))
        j = k + 1
    return out, j


def _parse_node(lines, k, indent):
    text = lines[k].strip()
    if text == '-' or text.startswith('- '):
        return _parse_seq(lines, k, indent)
    return _parse_map(lines, k, indent)


def parse_file(path):
    with open(path, encoding='utf-8') as f:
        lines = f.read().splitlines()
    doc, _ = _parse_map(lines, 0, 0)
    return doc


# ---------------------------------------------------------------------------
# Classification of individual shell lines into comparable checks.

def _strip_env_prefixes(s, env):
    """Fold leading VAR=value assignments into env; GitLab spells build env
    as command prefixes where GitHub uses a step env block."""
    while True:
        m = re.match(r'^([A-Z_][A-Z0-9_]*)=(\S+)\s+(.*)$', s)
        if not m:
            return s, env
        env = dict(env)
        env[m.group(1)] = m.group(2).strip('"')
        s = m.group(3)


def _classify(line, env, prov, add):
    s = line.strip()
    if not s or s.startswith('#'):
        return
    s = re.sub(r'^sudo\s+', '', s)
    s, env = _strip_env_prefixes(s, env)
    s = re.sub(r'\s+', ' ', s.replace('\\\n', ' ')).rstrip('\\').strip()
    if not s:
        return

    if s.startswith('go vet'):
        add('lint/vet', s, prov)
    elif s.startswith('golangci-lint'):
        # ./... is golangci-lint's default target; the action omits it.
        add('lint/golangci-lint', re.sub(r'\s*\./\.\.\.$', '', s), prov)
    elif re.search(r'(^|\$\()gofmt\b', s):
        add('lint/gofmt', re.search(r'gofmt\b.*', s).group(0).rstrip(')'), prov)
    elif s.startswith('go test'):
        if ' -race' in s:
            add('test/race', s, prov)
        elif '-coverprofile' in s:
            canon = s
            if env.get('CGO_ENABLED') is not None:
                canon = 'CGO_ENABLED=%s %s' % (env['CGO_ENABLED'], s)
            add('test/coverage', canon, prov)
        else:
            # Unknown go test shape: bucket it anyway so a one-sided
            # addition shows up as drift instead of being invisible.
            add('test/other', s, prov)
    elif s.startswith('go build'):
        goos, goarch = env.get('GOOS'), env.get('GOARCH')
        toks = shlex.split(s)
        if '-o' in toks:
            i = toks.index('-o')
            # The output path is runner plumbing (artifact name vs /dev/null).
            del toks[i:i + 2]
        prefix = []
        if env.get('CGO_ENABLED') is not None:
            prefix.append('CGO_ENABLED=%s' % env['CGO_ENABLED'])
        if goos and goarch:
            prefix += ['GOOS=%s' % goos, 'GOARCH=%s' % goarch]
            bucket = 'build/%s/%s' % (goos, goarch)
        else:
            bucket = 'build/native'
        add(bucket, ' '.join(prefix + toks), prov)
    elif s.startswith('go '):
        pass  # go install/version/env/tool cover: setup plumbing
    elif s.startswith('grep -v -E '):
        m = re.match(r"^grep -v -E '([^']*)'", s)
        # Drop the redirect and '|| true': both are runner plumbing.
        add('test/coverage-filter',
            "grep -v -E '%s'" % (m.group(1) if m else s), prov)
    elif s.startswith('awk '):
        m = re.search(r'exit \(c\+0 >= ([0-9.]+)\)', s)
        if m:
            add('test/coverage-gate', 'coverage-gate >= %g' % float(m.group(1)), prov)
    elif s.startswith('govulncheck'):
        add('security/govulncheck', s, prov)
    elif s.startswith('./scripts/fuzz.sh') or s.startswith('scripts/fuzz.sh'):
        add('fuzz', s[2:] if s.startswith('./') else s, prov)
    elif s.startswith('docker build'):
        m = re.match(r'^docker build -f (\S+)', s)
        if m:
            add('docker/%s' % m.group(1), 'docker build -f %s' % m.group(1), prov)
        else:
            add('docker/other', s, prov)
    elif s.startswith('nix flake check'):
        add('nix/flake-check', s, prov)
    elif s.startswith('nix develop'):
        add('nix/devshell-test', s, prov)
    elif s.startswith('goreleaser release'):
        add('release/goreleaser', s, prov)
    # Everything else — apt-get, command -v, echo, docker run, modprobe,
    # shell control flow — is runner plumbing, not the compared surface.


# ---------------------------------------------------------------------------
# Extractors.

def _expand_matrix(env, matrix, prov):
    """Expand ${{ matrix.x }} references in a step env over the matrix."""
    refs = sorted(set(re.findall(r'\$\{\{\s*matrix\.(\w+)\s*\}\}',
                                 json.dumps(env))))
    if not refs:
        return [(env, prov)]
    dims = []
    for r in refs:
        vals = matrix.get(r)
        if not isinstance(vals, list) or not vals:
            raise ParseError('%s: matrix.%s referenced but undefined' % (prov, r))
        dims.append([(r, str(v)) for v in vals])
    out = []
    for combo in product(*dims):
        def sub(s):
            for name, val in combo:
                s = re.sub(r'\$\{\{\s*matrix\.%s\s*\}\}' % name, val, str(s))
            return s
        out.append(({k: sub(v) for k, v in env.items()}, sub(prov)))
    return out


def extract_github(doc):
    checks = {}

    def add(bucket, canon, prov):
        checks.setdefault(bucket, []).append((canon, prov))

    jobs = doc.get('jobs')
    if not isinstance(jobs, dict):
        raise ParseError('%s: no jobs mapping' % GITHUB_CI)
    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            raise ParseError('%s: job %r is not a mapping' % (GITHUB_CI, job_name))
        matrix = {}
        strat = job.get('strategy')
        if isinstance(strat, dict) and isinstance(strat.get('matrix'), dict):
            matrix = strat['matrix']
        for step in job.get('steps') or []:
            if not isinstance(step, dict):
                raise ParseError('%s: job %r has a non-mapping step' % (GITHUB_CI, job_name))
            label = step.get('name') or step.get('uses') or '?'
            prov = 'github: %s / %s' % (job_name, label)
            uses = str(step.get('uses') or '')
            if 'golangci-lint-action' in uses:
                with_ = step.get('with') or {}
                args = str(with_.get('args') or '').strip()
                add('lint/golangci-lint',
                    ' '.join(x for x in ('golangci-lint run', args) if x), prov)
            run = step.get('run')
            if run is None:
                continue
            for env_i, prov_i in _expand_matrix(step.get('env') or {}, matrix, prov):
                for line in str(run).splitlines():
                    _classify(line, env_i, prov_i, add)
    return checks, sorted(jobs)


def extract_gitlab(doc):
    checks = {}

    def add(bucket, canon, prov):
        checks.setdefault(bucket, []).append((canon, prov))

    variables = doc.get('variables')
    global_env = dict(variables) if isinstance(variables, dict) else {}
    stages = doc.get('stages') if isinstance(doc.get('stages'), list) else []
    job_names = []
    for name, job in doc.items():
        if name in ('stages', 'variables', 'include', 'workflow', 'default'):
            continue
        if name.startswith('.'):  # hidden templates hold anchors only
            continue
        if not isinstance(job, dict):
            raise ParseError('%s: job %r is not a mapping' % (GITLAB_CI, name))
        job_names.append(name)
        prov = 'gitlab: %s (%s)' % (name, job.get('stage') or '-')
        script = job.get('script') or []
        if not isinstance(script, list):
            raise ParseError('%s: job %r script is not a list' % (GITLAB_CI, name))
        for item in script:
            for line in str(item).splitlines():
                _classify(line, dict(global_env), prov, add)
    return checks, (stages, sorted(job_names))


# ---------------------------------------------------------------------------
# Comparison and report.

def normalize(raw):
    return {b: sorted({c for c, _ in v}) for b, v in raw.items()}


def main():
    args = sys.argv[1:]
    verbose = any(a in ('-v', '--verbose') for a in args)
    root = next((a for a in args if not a.startswith('-')), None)
    if root is None:
        print('usage: scripts/ci-parity.sh [--verbose]', file=sys.stderr)
        return 2

    gh_raw, gh_jobs = extract_github(parse_file(os.path.join(root, GITHUB_CI)))
    gl_raw, (gl_stages, gl_jobs) = extract_gitlab(parse_file(os.path.join(root, GITLAB_CI)))
    gh, gl = normalize(gh_raw), normalize(gl_raw)

    provenance = {}
    for side, raw in (('github', gh_raw), ('gitlab', gl_raw)):
        for bucket, entries in raw.items():
            for canon, prov in entries:
                provenance.setdefault((side, bucket, canon), prov)

    broken = [b for b in REQUIRED if b not in gh or b not in gl]
    if not any(b.startswith('build/') for b in gh) or \
       not any(b.startswith('build/') for b in gl):
        broken.append('build/<goos>/<goarch>')
    if broken:
        print('ci-parity: cannot trust the extraction — these expected checks '
              'were not found on both sides:\n  ' + '\n  '.join(broken) +
              '\nEither the mini-parser broke on a restructured file, or the '
              'CI legitimately changed; fix one or update the script.',
              file=sys.stderr)
        return 2

    drift = []
    notes = []
    shared = 0
    onesided = 0
    for bucket in sorted(set(gh) | set(gl)):
        a, b = gh.get(bucket, []), gl.get(bucket, [])
        if a == b and a:
            shared += 1
            if bucket in PLATFORM_ONLY:
                notes.append('%s: present on both sides now; consider removing '
                             'it from the one-sided allowlist' % bucket)
            continue
        if bucket in PLATFORM_ONLY and (not a or not b):
            onesided += 1
            continue
        drift.append((bucket, a, b))
    for bucket in sorted(PLATFORM_ONLY):
        if bucket not in gh and bucket not in gl:
            notes.append('%s: allowlisted as one-sided but missing from both CIs'
                         % bucket)

    if verbose:
        print('github jobs: %s' % ', '.join(gh_jobs))
        print('gitlab stages: %s' % ', '.join(gl_stages))
        print('gitlab jobs: %s' % ', '.join(gl_jobs))
        for bucket in sorted(set(gh) | set(gl)):
            where = 'both' if bucket in gh and bucket in gl else \
                    'github' if bucket in gh else 'gitlab'
            for canon in sorted(set(gh.get(bucket, []) + gl.get(bucket, []))):
                print('  [%-6s] %-28s %s' % (where, bucket, canon))
        print()

    for note in notes:
        print('note: ' + note)

    if drift:
        print('ci-parity: DRIFT — the two CI definitions disagree:')
        for bucket, a, b in drift:
            print('\n  ' + bucket)
            for side, cmds in (('github', a), ('gitlab', b)):
                if not cmds:
                    print('    %-7s MISSING' % side)
                for canon in cmds:
                    print('    %-7s %s' % (side, canon))
                    print('            %s' % provenance.get((side, bucket, canon), ''))
        print('\nSynchronize .github/workflows/ci.yml and .gitlab-ci.yml, or — '
              'if the check is genuinely one-sided — add it to PLATFORM_ONLY '
              'in scripts/ci-parity.sh with a reason.')
        return 1

    print('ci-parity: OK — %d checks identical on both sides, '
          '%d one-sided (documented exceptions)' % (shared, onesided))
    return 0


sys.exit(main())
PY
