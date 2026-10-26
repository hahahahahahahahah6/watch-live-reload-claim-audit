"""Static documentation and filesystem-observation audit."""
import argparse
import ast
import fnmatch
import json
from pathlib import Path
import re
import sys

__version__ = "0.1.0"
WATCH = (
    "watches for file changes", "watches for changes", "watches the file system",
    "watches the filesystem", "watches files for changes", "watches files",
    "watches the directory", "watches a directory", "watches directories",
    "file watching support", "file watching enabled", "automatic reload on change",
    "automatically reloads on change", "reloads automatically on change",
    "reloads on file change", "reloads when files change", "live reload support",
    "live reload enabled", "live reload", "hot reload support", "hot reload enabled",
    "hot reload", "auto reload support", "auto reload enabled", "auto reload",
    "automatically reloads", "reloads automatically", "file change detection",
    "detects file changes", "monitors files for changes", "monitors files",
    "monitors file changes",
)
NOWATCH = (
    "does not watch files", "does not watch for changes", "never watches files",
    "does not support live reload", "does not support hot reload",
    "does not support auto reload", "no live reload support", "no live reload",
    "no hot reload", "no auto reload", "no file watching", "no file watching support",
    "without live reload", "without file watching", "does not reload automatically",
    "never reloads automatically", "must be restarted manually",
    "requires a manual restart", "manual restart required",
)


def claims(text):
    """Extract at most one family per normalized prose sentence."""
    prose = []
    fence = None
    for number, line in enumerate(text.splitlines(), 1):
        match = re.match(r"^\s{0,3}(`{3,}|~{3,})", line)
        if match:
            marker = match.group(1)
            if fence is None:
                fence = marker
            elif marker[0] == fence[0] and len(marker) >= len(fence):
                fence = None
            continue
        if fence is None:
            prose.append((number, line))
    phrases = sorted([(p, "WATCH") for p in WATCH] + [(p, "NOWATCH") for p in NOWATCH],
                     key=lambda item: -len(item[0]))
    result = []
    for number, line in prose:
        line = line.lower().replace("n’t", " not").replace("n't", " not").replace("-", " ")
        for sentence in re.split(r"[.!?\n]+", line):
            sentence = " ".join(sentence.split())
            for phrase, family in phrases:
                match = re.search(r"(?<!\w)" + re.escape(phrase) + r"(?!\w)", sentence)
                if match:
                    remainder = sentence[:match.start()] + " " + sentence[match.end():]
                    if family != "WATCH" or not re.search(r"\b(no|not|never|without)\b", remainder):
                        result.append({"family": family, "phrase": phrase, "line": number})
                    break
    return result


def evidence(text):
    """Resolve imported aliases and reject module-local shadowing."""
    tree = ast.parse(text)
    aliases, shadowed = {}, set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                aliases[alias.asname or alias.name.split('.')[0]] = alias.name if alias.asname else alias.name.split('.')[0]
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                aliases[alias.asname or alias.name] = (node.module or '') + '.' + alias.name
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            shadowed.add(node.name)
        elif isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            shadowed.add(node.id)
        elif isinstance(node, ast.arg):
            shadowed.add(node.arg)
    def name(node):
        if isinstance(node, ast.Name):
            if node.id in shadowed:
                return ''
            return aliases.get(node.id, '')
        if isinstance(node, ast.Attribute):
            base = name(node.value)
            return base + '.' + node.attr if base else ''
        if isinstance(node, ast.Call):
            return name(node.func) + '()'
        return ''
    # Track constructor-derived objects without treating their assignment as an import shadow.
    objects = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)) and isinstance(node.value, ast.Call):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, ast.Name):
                    objects[target.id] = name(node.value.func)
    def callname(node):
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            base = objects.get(node.value.id)
            if base:
                return base + '().' + node.attr
        return name(node)
    found = []
    def add(node, kind):
        item = {"line": node.lineno, "kind": kind}
        if item not in found:
            found.append(item)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            resolved = callname(node.func)
            tail = resolved.rsplit('.', 1)[-1]
            if resolved.startswith('watchdog.') and tail in {'Observer', 'PollingObserver', 'PollingObserverVFS', 'schedule', 'observe'}:
                add(node, 'watchdog')
            if resolved.startswith('watchfiles.') and tail in {'watch', 'awatch'}:
                add(node, 'watchfiles')
            if resolved.startswith(('inotify.', 'inotify_simple.')) and tail in {'INotify', 'add_watch'}:
                add(node, 'inotify')
            if any(k.arg in {'reload', 'use_reloader'} and isinstance(k.value, ast.Constant) and k.value.value is True for k in node.keywords):
                add(node, 'reload-flag')
        elif isinstance(node, ast.ClassDef):
            if any(name(base).startswith('watchdog.') and name(base).rsplit('.', 1)[-1] in {'FileSystemEventHandler', 'PatternMatchingEventHandler', 'RegexMatchingEventHandler'} for base in node.bases):
                add(node, 'watchdog-handler')
        if isinstance(node, (ast.For, ast.While, ast.AsyncFor)):
            calls = [callname(n.func) for statement in node.body for n in ast.walk(statement) if isinstance(n, ast.Call)]
            stats = {'os.path.getmtime', 'os.path.getctime', 'os.stat', 'os.lstat', 'pathlib.Path.stat', 'pathlib.Path().stat'}
            if 'time.sleep' in calls and any(c in stats for c in calls):
                add(node, 'change-polling')
    return found


def audit(root, ignores=()):
    root = Path(root)
    if not root.is_dir():
        raise OSError('project root is not a directory: ' + str(root))
    extracted, production, tests = [], [], []
    def excluded(rel):
        return any(fnmatch.fnmatch(rel.as_posix(), pattern) or pattern.rstrip('/') in rel.parts or rel.as_posix().startswith(pattern.rstrip('/') + '/') for pattern in ignores)
    def walk(directory):
        for path in sorted(directory.iterdir()):
            rel = path.relative_to(root)
            if path.is_symlink() or excluded(rel) or any(p in {'.venv', '.git', '__pycache__', 'build', 'dist'} or p.endswith('.egg-info') for p in rel.parts):
                continue
            if path.is_dir():
                yield from walk(path)
            else:
                yield path, rel
    for path, rel in walk(root):
        if rel.as_posix() == 'README.md' or (rel.parts[0] == 'docs' and path.suffix == '.md'):
            for item in claims(path.read_text(encoding='utf-8')):
                extracted.append(dict(item, path=rel.as_posix()))
        if path.suffix != '.py':
            continue
        if any(p in {'fixtures', 'docs', 'examples'} for p in rel.parts[:-1]):
            continue
        target = tests if 'tests' in rel.parts[:-1] or path.name.startswith('test_') or path.name.endswith('_test.py') else production
        for item in evidence(path.read_text(encoding='utf-8')):
            target.append(dict(item, path=rel.as_posix()))
    findings = []
    for family in ('WATCH', 'NOWATCH'):
        selected = [c for c in extracted if c['family'] == family]
        if not selected:
            continue
        severity = None
        if family == 'WATCH' and not production:
            severity = 'MEDIUM' if tests else 'HIGH'
        elif family == 'NOWATCH':
            severity = 'HIGH' if production else ('MEDIUM' if tests else None)
        if severity:
            findings.append({'rule': 'documented-' + ('watch' if family == 'WATCH' else 'no-watch') + '-claim-false', 'severity': severity, 'claims': selected})
    return {'status': 'FAIL' if findings else 'PASS', 'findings': findings, 'claims': extracted, 'production_evidence': production, 'test_evidence': tests}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', nargs='?', default='.')
    parser.add_argument('--version', action='version', version=__version__)
    parser.add_argument('--json', action='store_true')
    parser.add_argument('--verbose', action='store_true')
    parser.add_argument('--ignore', action='append', default=[])
    parser.add_argument('--fail-on', choices=['HIGH'])
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return 1 if exc.code else 0
    try:
        result = audit(args.root, args.ignore)
    except (OSError, UnicodeError, SyntaxError) as exc:
        print('error: ' + str(exc), file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(result['status'])
        for finding in result['findings']:
            print(f"{finding['severity']} {finding['rule']}")
        if args.verbose:
            for key in ('claims', 'production_evidence', 'test_evidence'):
                for item in result[key]:
                    print(key + ': ' + json.dumps(item))
    return 2 if any(not args.fail_on or f['severity'] == args.fail_on for f in result['findings']) else 0
