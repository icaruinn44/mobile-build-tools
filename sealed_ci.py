"""Generic authenticated-encryption wrapper for owner-triggered private mobile builds."""
from pathlib import Path
import base64, hashlib, io, json, os, subprocess, sys, urllib.request, zipfile
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
    url='https://github.com/icaruinn44/mobile-build-tools/releases/download/input-20261108/sealed-input.bin'
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
        result=subprocess.run(['bash','ci/run_sealed_candidate.sh',stage],cwd=SOURCE,stdout=log,stderr=subprocess.STDOUT)
    print(stage+': '+('passed' if result.returncode==0 else 'failed; detailed diagnostics are encrypted'))
    raise SystemExit(result.returncode)
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
    else: run(sys.argv[1])
