"""Generic authenticated-encryption wrapper for owner-triggered private mobile builds."""
from pathlib import Path
import base64, hashlib, io, json, os, plistlib, re, subprocess, sys, urllib.request, zipfile
from PIL import Image
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ROOT=Path(__file__).resolve().parent
SOURCE=ROOT/'payload'
LOGS=ROOT/'private-logs'
STAGES={'deps','startup','sign','archive','upload'}
def crypto():
    key=base64.b64decode(os.environ['PAYLOAD_KEY'],validate=True)
    assert len(key)==32
    return AESGCM(key)
def initialize():
    url='https://github.com/icaruinn44/mobile-build-tools/releases/download/input-rapidfo59-20261109/sealed-input.bin'
    with urllib.request.urlopen(url,timeout=120) as response: data=response.read()
    assert hashlib.sha256(data).hexdigest()==os.environ['INPUT_SHA256']
    assert data[:9]==b'MOBILECI1'
    plain=crypto().decrypt(data[9:21],data[21:],b'mobile-ci-input-v1')
    SOURCE.mkdir(exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(plain)) as z:
        for entry in z.infolist():
            path=(SOURCE/entry.filename).resolve()
            assert path.is_relative_to(SOURCE.resolve()) and not (entry.external_attr>>16)&0o170000==0o120000
        z.extractall(SOURCE)
    # Archives produced on Windows can apply core.autocrlf checkout conversion.
    # Native shell build phases require Unix line endings, as on a Mac checkout.
    for folder in (SOURCE/'ci', SOURCE/'ios/scripts'):
        if folder.exists():
            for script in folder.rglob('*.sh'):
                content=script.read_bytes()
                if b'\r\n' in content: script.write_bytes(content.replace(b'\r\n',b'\n'))
    LOGS.mkdir(exist_ok=True)
    print('Encrypted build input authenticated and opened.')
def run(stage):
    assert stage in STAGES
    LOGS.mkdir(exist_ok=True)
    with (LOGS/(stage+'.log')).open('wb') as log:
        if stage=='startup' and os.environ.get('VERIFIED_STARTUP_RUN'):
            command=[sys.executable,str(ROOT/'sealed_ci.py'),'reuse-startup',os.environ['VERIFIED_STARTUP_RUN']]
        elif stage=='startup' and os.environ.get('STARTUP_METHOD')=='standalone':
            command=[sys.executable,str(ROOT/'standalone_startup.py')]
        else:
            command=[sys.executable,str(ROOT/'signing.py')] if stage=='sign' else ['bash','ci/run_sealed_candidate.sh',stage]
        result=subprocess.run(command,cwd=SOURCE,stdout=log,stderr=subprocess.STDOUT)
    print(stage+': '+('passed' if result.returncode==0 else 'failed; detailed diagnostics are encrypted'))
    if result.returncode:
        log=(LOGS/(stage+'.log')).read_text(encoding='utf-8',errors='replace')
        categories=[('Native main-app startup image is blank','BLANK_NATIVE_FRAME'),('did not reach landscape','ORIENTATION_NOT_LANDSCAPE'),('TimeoutException after 0:00:15','FIRST_FRAME_WAIT_TIMEOUT'),('did not progress past the startup splash','BOOTSTRAP_TIMEOUT'),('MAC verification failed','CERTIFICATE_IMPORT_FORMAT'),('Could not build the application','NATIVE_COMPILATION_FAILED'),('Native application process is not running','NATIVE_PROCESS_STOPPED'),('Normal Flutter launcher exited','FLUTTER_LAUNCH_FAILED')]
        print('Failure category: '+next((code for pattern,code in categories if pattern in log),'OTHER_ENCRYPTED_DIAGNOSTIC'))
    raise SystemExit(result.returncode)
def reuse_startup(run_id):
    assert re.fullmatch(r'\d+',run_id)
    url='https://github.com/icaruinn44/mobile-build-tools/releases/download/result-'+run_id+'/encrypted-result.bin'
    with urllib.request.urlopen(url,timeout=120) as response: data=response.read()
    assert data[:8]==b'MOBILER1'
    plain=crypto().decrypt(data[8:20],data[20:],b'mobile-ci-result-v1')
    current=json.loads((SOURCE/'ci/candidate-metadata.json').read_text())
    with zipfile.ZipFile(io.BytesIO(plain)) as z:
        previous=json.loads(z.read('candidate-metadata.json'))
        assert previous==current,'A startup proof may only be reused for the identical frozen candidate'
        before=z.read('logs/deps.log').decode('utf-8',errors='replace')
        now=(LOGS/'deps.log').read_text(encoding='utf-8',errors='replace')
        def versions(log):
            log=re.sub(r'\x1b\[[0-9;]*[A-Za-z]','',log).replace('\r\n','\n')
            return sorted(re.findall(r'^(?:Installing .+ \(.+\)|Xcode \S+|Build version \S+)$',log,re.M))
        assert versions(before)==versions(now) and len(versions(now))>20,'Toolchain or native dependency versions changed'
        evidence=SOURCE/'ios-release-evidence'
        (evidence/'iphone').mkdir(parents=True,exist_ok=True)
        image_bytes=z.read('evidence/iphone/actual-main-startup.png')
        (evidence/'iphone/actual-main-startup-raw.png').write_bytes(image_bytes)
        normalized=False
        if 'evidence/actual-main-startup.json' in z.namelist():
            proof=json.loads(z.read('evidence/actual-main-startup.json'))
            assert proof['nonblank'] and proof['entrypoint']=='lib/main.dart' and proof['iosPurchasesEnabled']
        else:
            # Recover a real, already-running main capture rejected solely for
            # simctl's physical portrait framebuffer dimensions. The source app
            # permits landscape only. Preserve the untouched raw frame as proof.
            startup_log=z.read('logs/startup.log').decode('utf-8',errors='replace')
            launcher=z.read('evidence/flutter-main-launcher.log').decode('utf-8',errors='replace')
            assert 'AssertionError: Actual main() did not reach landscape orientation' in startup_log
            assert 'standalone_startup.py' in startup_log and '"event":"app.started"' in launcher
            assert 'Native application process is not running' not in startup_log
            info=plistlib.loads((SOURCE/'ios/Runner/Info.plist').read_bytes())
            assert set(info['UISupportedInterfaceOrientations'])=={'UIInterfaceOrientationLandscapeLeft','UIInterfaceOrientationLandscapeRight'}
            raw=Image.open(io.BytesIO(image_bytes))
            assert raw.width<raw.height
            rotated=raw.transpose(Image.Transpose.ROTATE_90)
            assert rotated.transpose(Image.Transpose.ROTATE_270).tobytes()==raw.tobytes()
            output=io.BytesIO(); rotated.save(output,format='PNG'); image_bytes=output.getvalue(); normalized=True
            proof={'entrypoint':'lib/main.dart','iosPurchasesEnabled':True,'driver':'flutter run --machine + simctl','nativeProcessVerified':True,'captureNormalization':'90-degree lossless rotation from physical portrait framebuffer to app landscape layout','rawCaptureSha256':hashlib.sha256(z.read('evidence/iphone/actual-main-startup.png')).hexdigest()}
        (evidence/'iphone/actual-main-startup.png').write_bytes(image_bytes)
    subprocess.run([sys.executable,'ci/check_startup_image.py'],cwd=SOURCE,check=True)
    checked=json.loads((evidence/'actual-main-startup.json').read_text()); checked.update(proof)
    (evidence/'actual-main-startup.json').write_text(json.dumps(checked,indent=2))
    (evidence/'startup-proof-source.json').write_text(json.dumps({'runId':run_id,'sourceCommit':current['sourceCommit'],'sameNativeDependencyVersions':True}))
    print('Reused verified native startup for the identical frozen source and native dependency versions, run '+run_id+'; lossless capture orientation correction: '+str(normalized))
def package():
    buffer=io.BytesIO()
    with zipfile.ZipFile(buffer,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=3) as z:
        for folder,prefix in [(LOGS,'logs'),(SOURCE/'ios-release-evidence','evidence'),(SOURCE/'build/ios/ipa','ipa')]:
            if folder.exists():
                for f in folder.rglob('*'):
                    if f.is_file(): z.write(f,prefix+'/'+f.relative_to(folder).as_posix())
        metadata=SOURCE/'ci/candidate-metadata.json'
        if metadata.exists(): z.write(metadata,'candidate-metadata.json')
    nonce=os.urandom(12)
    sealed=b'MOBILER1'+nonce+crypto().encrypt(nonce,buffer.getvalue(),b'mobile-ci-result-v1')
    (ROOT/'encrypted-result.bin').write_bytes(sealed)
    print('Only authenticated ciphertext will be saved as the build artifact.')
if __name__=='__main__':
    if sys.argv[1]=='init': initialize()
    elif sys.argv[1]=='package': package()
    elif sys.argv[1]=='reuse-startup': reuse_startup(sys.argv[2])
    else: run(sys.argv[1])
