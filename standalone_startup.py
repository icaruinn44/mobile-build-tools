"""Verify a real Flutter main cold start with its normal resident launcher."""
from pathlib import Path
import json, os, subprocess, sys, threading, time

evidence=Path('ios-evidence'); (evidence/'iphone').mkdir(parents=True,exist_ok=True)
devices=json.loads(subprocess.check_output(['xcrun','simctl','list','devices','available','-j']))
device=next(d['udid'] for group in devices['devices'].values() for d in group if d['isAvailable'] and 'Pro Max' in d['name'])
subprocess.run(['xcrun','simctl','boot',device],check=True)
subprocess.run(['xcrun','simctl','bootstatus',device,'-b'],check=True)
started=threading.Event()
process=subprocess.Popen(['flutter','run','--machine','--debug','--no-pub','-d',device,'--target=lib/main.dart','--dart-define-from-file=config/admob_ios.json','--dart-define=IOS_PURCHASES_ENABLED=true'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,bufsize=1)
def observe():
    with (evidence/'flutter-main-launcher.log').open('w',encoding='utf-8') as log:
        for line in process.stdout:
            log.write(line); log.flush()
            try: events=json.loads(line)
            except (ValueError,TypeError): continue
            if isinstance(events,list) and any(isinstance(e,dict) and e.get('event')=='app.started' for e in events): started.set()
reader=threading.Thread(target=observe,daemon=True); reader.start()
try:
    deadline=time.monotonic()+1500
    while not started.wait(1):
        assert process.poll() is None,'Normal Flutter launcher exited before starting main'
        assert time.monotonic()<deadline,'Normal Flutter launcher start timeout'
    time.sleep(30)
    assert process.poll() is None,'Normal Flutter launcher lost the application'
    services=subprocess.check_output(['xcrun','simctl','spawn',device,'launchctl','list'],text=True)
    app_rows=[line.split() for line in services.splitlines() if os.environ['BUNDLE_ID'] in line]
    assert any(row[0].isdigit() and int(row[0])>0 for row in app_rows),'Native application process is not running'
    path=evidence/'iphone/actual-main-startup.png'
    subprocess.run(['xcrun','simctl','io',device,'screenshot',str(path)],check=True,timeout=120)
    subprocess.run([sys.executable,'ci/check_startup_image.py'],check=True)
    data=json.loads((evidence/'actual-main-startup.json').read_text())
    data.update(driver='flutter run --machine + simctl',nativeProcessVerified=True)
    (evidence/'actual-main-startup.json').write_text(json.dumps(data,indent=2))
    print('Verified live native main process and nonblank landscape cold-start frame.')
finally:
    with (evidence/'simulator-log.txt').open('w') as log:
        try: subprocess.run(['xcrun','simctl','spawn',device,'log','show','--last','3m','--style','compact','--predicate','process == "Runner"'],stdout=log,stderr=subprocess.STDOUT,timeout=120)
        except subprocess.TimeoutExpired: pass
    process.terminate()
    try: process.wait(timeout=15)
    except subprocess.TimeoutExpired: process.kill()
    reader.join(timeout=5)
    subprocess.run(['xcrun','simctl','shutdown',device],check=False)
