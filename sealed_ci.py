"""Generic authenticated-encryption wrapper for owner-triggered private mobile builds."""
from pathlib import Path
import base64, hashlib, io, json, os, re, subprocess, sys, urllib.request, zipfile
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
    url='https://github.com/icaruinn44/mobile-build-tools/releases/download/input-judge52-20261108-v2/sealed-input-v2.bin'
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
        else:
            command=[sys.executable,str(ROOT/'signing.py')] if stage=='sign' else ['bash','ci/run_sealed_candidate.sh',stage]
        result=subprocess.run(command,cwd=SOURCE,stdout=log,stderr=subprocess.STDOUT)
    print(stage+': '+('passed' if result.returncode==0 else 'failed; detailed diagnostics are encrypted'))
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
            return sorted(re.findall(r'^(?:Installing .+ \(.+\)|Xcode \S+|Build version \S+)$',log,re.M))
        assert versions(before)==versions(now) and len(versions(now))>20,'Toolchain or native dependency versions changed'
        evidence=SOURCE/'ios-evidence'
        (evidence/'iphone').mkdir(parents=True,exist_ok=True)
        for name in ['actual-main-startup.json','iphone/actual-main-startup.png']:
            (evidence/name).write_bytes(z.read('evidence/'+name))
    proof=json.loads((evidence/'actual-main-startup.json').read_text())
    assert proof['nonblank'] and proof['entrypoint']=='lib/main.dart' and proof['iosPurchasesEnabled']
    subprocess.run([sys.executable,'ci/check_startup_image.py'],cwd=SOURCE,check=True)
    (evidence/'startup-proof-source.json').write_text(json.dumps({'runId':run_id,'sourceCommit':current['sourceCommit'],'sameNativeDependencyVersions':True}))
    print('Reused verified native startup for the identical frozen source and native dependency versions, run '+run_id)
def package():
    buffer=io.BytesIO()
    with zipfile.ZipFile(buffer,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=3) as z:
        for folder,prefix in [(LOGS,'logs'),(SOURCE/'ios-evidence','evidence'),(SOURCE/'build/ios/ipa','ipa')]:
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
