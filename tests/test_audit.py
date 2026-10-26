import json
import os
from pathlib import Path
import subprocess
import sys

import pytest
from watch_live_reload_claim_audit import WATCH, NOWATCH, audit, claims, evidence

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / 'tests/fixtures'

@pytest.mark.parametrize('phrase', WATCH)
def test_watch_phrases(phrase):
    assert [c['family'] for c in claims(phrase)] == ['WATCH']

@pytest.mark.parametrize('phrase', NOWATCH)
def test_nowatch_phrases(phrase):
    assert [c['family'] for c in claims(phrase)] == ['NOWATCH']

@pytest.mark.parametrize('text', ['watch reload monitor', 'not live reload', "doesn't have live reload", 'never monitors files', 'without hot reload', 'no watches files', '```text\nlive reload\n```', '~~~\nwatches files\n~~~'])
def test_no_claim(text):
    assert claims(text) == []

@pytest.mark.parametrize('text,phrase', [('LIVE-RELOAD','live reload'), ('Tool `watches files`.','watches files'), ('no live reload support','no live reload support'), ('never watches files','never watches files'), ('watches files for changes','watches files for changes')])
def test_normalize_longest(text, phrase):
    assert [c['phrase'] for c in claims(text)] == [phrase]

POSITIVE = [
 'import watchdog\nwatchdog.observe(".")',
 'from watchdog.observers import Observer\nObserver()',
 'from watchdog.observers.polling import PollingObserver\nPollingObserver()',
 'from watchdog.observers.polling import PollingObserverVFS as P\nP()',
 'from watchdog.observers import Observer\no=Observer()\no.schedule(None,".")',
 'from watchfiles import watch as w\nw(".")',
 'import watchfiles as wf\nwf.awatch(".")',
 'from inotify_simple import INotify\ni=INotify()\ni.add_watch(".")',
 'import inotify.adapters\ninotify.adapters.INotify()',
 'import inotify\ninotify.add_watch(".")',
 'run(reload=True)', 'anything(use_reloader=True)',
] + ['from watchdog.events import '+handler+' as H\nclass Events(H):\n pass' for handler in ['FileSystemEventHandler','PatternMatchingEventHandler','RegexMatchingEventHandler']] + ['import os,time\nwhile True:\n if True:\n  '+stat+'("x")\n time.sleep(1)' for stat in ['os.path.getmtime','os.path.getctime','os.stat','os.lstat']] + [
 'from pathlib import Path\nimport time\nfor x in []:\n Path("x").stat()\n time.sleep(1)',
 'from pathlib import Path\nimport time\np=Path("x")\nwhile True:\n p.stat()\n time.sleep(1)',
 'from os import stat as s\nfrom time import sleep as z\nfor x in []:\n s(x)\n z(1)',
]
@pytest.mark.parametrize('code', POSITIVE)
def test_evidence(code):
    assert evidence(code)

NEGATIVE = ['import watchdog', 'import watchfiles', 'import inotify', 'import inotify_simple', 'import time\ntime.sleep(1)', 'import os\nos.stat("x")', 'import os\nwhile True:\n os.path.getmtime("x")', 'import os\nos.listdir(".")', 'import os\nos.scandir(".")', 'import glob\nglob.glob("*")', 'from pathlib import Path\nPath(".").iterdir()', 'open("x").read()', 'run(reload=False,use_reloader=False)', '# run(reload=True)\n"run(reload=True)"', 'def watch():\n pass', 'def reload():\n pass', 'def observe():\n pass', 'from watchfiles import watch\ndef watch():\n pass\nwatch()', 'from watchdog.observers import Observer\nclass Observer:\n pass\nObserver()', 'import watchfiles\nwatchfiles=object()\nwatchfiles.watch()', 'import os,time\nos.stat("x")\nwhile True:\n time.sleep(1)', 'import os,time\nwhile True:\n os.stat("x")\nelse:\n time.sleep(1)']
@pytest.mark.parametrize('code', NEGATIVE)
def test_exclusions(code):
    assert evidence(code) == []

@pytest.mark.parametrize('name', ['good/watch','good/watch-poll','good/watch-flag','good/nowatch','nosource/nowatch','guards/fenced'])
def test_pass(name):
    assert audit(FIX/name)['findings'] == []

@pytest.mark.parametrize('name,family,severity', [('bad/watch','watch','HIGH'),('bad/nowatch','no-watch','HIGH'),('nosource/watch','watch','HIGH'),('testonly/watch','watch','MEDIUM'),('testonly/nowatch','no-watch','MEDIUM')] + [('guards/'+n,'watch','HIGH') for n in ['inline','bare-import','sleep','poll-no-sleep','listdir','false-flag','named-watch']])
def test_findings(name,family,severity):
    findings = audit(FIX/name)['findings']
    assert len(findings) == 1
    assert findings[0]['rule'] == 'documented-'+family+'-claim-false'
    assert findings[0]['severity'] == severity

@pytest.mark.parametrize('directory', ['tests','fixtures','docs','examples'])
def test_source_directories(tmp_path,directory):
    (tmp_path/'README.md').write_text('watches files')
    (tmp_path/directory).mkdir()
    (tmp_path/directory/'app.py').write_text('run(reload=True)')
    result=audit(tmp_path)
    assert result['production_evidence'] == []
    assert result['findings'][0]['severity'] == ('MEDIUM' if directory=='tests' else 'HIGH')

@pytest.mark.parametrize('filename', ['test_app.py','app_test.py'])
def test_test_names(tmp_path,filename):
    (tmp_path/'README.md').write_text('no live reload')
    (tmp_path/filename).write_text('run(reload=True)')
    assert audit(tmp_path)['findings'][0]['severity']=='MEDIUM'

def test_docs_ignore_symlinks_and_env(tmp_path,monkeypatch):
    (tmp_path/'docs/sub').mkdir(parents=True)
    (tmp_path/'docs/sub/guide.md').write_text('watches files')
    (tmp_path/'README.md').symlink_to(tmp_path/'docs/sub/guide.md')
    (tmp_path/'app.py').symlink_to(FIX/'good/watch-flag/app.py')
    (tmp_path/'.env').write_bytes(b'\xff')
    original=Path.open
    def guarded(path,*args,**kwargs):
        assert path.name != '.env'
        return original(path,*args,**kwargs)
    monkeypatch.setattr(Path,'open',guarded)
    assert len(audit(tmp_path)['findings']) == 1
    assert audit(tmp_path,['docs'])['findings'] == []
    assert audit(tmp_path,['docs/**/*.md'])['findings'] == []

def test_self():
    assert audit(ROOT)['status']=='PASS'

def cli(*args,console=False):
    return subprocess.run((['watch-live-reload-claim-audit'] if console else [sys.executable,'-m','watch_live_reload_claim_audit'])+list(map(str,args)),capture_output=True,text=True)

@pytest.mark.parametrize('console',[False,True])
def test_entrypoints(console):
    assert cli('--version',console=console).stdout.strip()=='0.1.0'
    assert cli(FIX/'good/watch',console=console).returncode==0
    result=cli(FIX/'bad/watch','--json',console=console)
    assert result.returncode==2
    assert json.loads(result.stdout)['findings'][0]['severity']=='HIGH'

@pytest.mark.parametrize('name',['watch','nowatch'])
def test_medium_cli(name):
    assert cli(FIX/'testonly'/name).returncode==2
    assert cli(FIX/'testonly'/name,'--fail-on','HIGH').returncode==0

@pytest.mark.parametrize('args',[['--unknown'],['--fail-on','LOW'],['/nonexistent-project']])
def test_errors(args):
    assert cli(*args).returncode==1

def test_ignore_verbose_cli():
    assert cli(FIX/'bad/watch','--ignore','README.md','--ignore','app.py').returncode==0
    assert 'production_evidence' in cli(FIX/'good/watch','--verbose').stdout

def test_invalid_source(tmp_path):
    (tmp_path/'app.py').write_text('def !')
    assert cli(tmp_path).returncode==1
