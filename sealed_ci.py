"""Owner-only authenticated encryption and execution for mobile build inputs."""
import base64
import hashlib
import io
import os
from pathlib import Path
import subprocess
import sys
import urllib.request
import zipfile
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ROOT=Path(__file__).resolve().parent
SOURCE=ROOT/'payload'
LOGS=ROOT/'private-logs'
def cipher():
    key=base64.b64decode(os.environ['PAYLOAD_KEY'],validate=True)
    assert len(key)==32
    return AESGCM(key)
def initialize():
    url='https://github.com/icaruinn44/mobile-build-tools/releases/download/input-mistik67-20261109-v8/sealed-mistik67-input-v8.bin'
    with urllib.request.urlopen(url,timeout=120) as response:data=response.read()
    assert hashlib.sha256(data).hexdigest()==os.environ['INPUT_SHA256'] and data[:9]==b'MOBILECI1'
    plain=cipher().decrypt(data[9:21],data[21:],b'mobile-ci-input-v1')
    SOURCE.mkdir(exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(plain)) as archive:
        for entry in archive.infolist():
            target=(SOURCE/entry.filename).resolve()
            assert target.is_relative_to(SOURCE.resolve()) and (entry.external_attr>>16)&0o170000!=0o120000
        archive.extractall(SOURCE)
    LOGS.mkdir(exist_ok=True)
    print('Authenticated private build input opened.')
def run(stage):
    assert stage in {'deps','startup','sign','archive','upload'}
    script=SOURCE/'ci/run_sealed_candidate.sh'
    content=script.read_bytes().replace(b'\r\n',b'\n').decode()
    if stage=='sign':
        content=content.replace('from cryptography.hazmat.primitives.serialization import pkcs12,Encoding',
            'from cryptography.hazmat.primitives.serialization import pkcs12,Encoding,PrivateFormat\nfrom cryptography.hazmat.primitives import hashes')
        old="keyfile.write_bytes(base64.b64decode(os.environ['IOS_CERTIFICATE_BASE64']))"
        new="keyfile.write_bytes(pkcs12.serialize_key_and_certificates(b'Distribution',key,certificate,None,PrivateFormat.PKCS12.encryption_builder().kdf_rounds(50000).key_cert_algorithm(pkcs12.PBES.PBESv1SHA1And3KeyTripleDESCBC).hmac_hash(hashes.SHA1()).build(os.environ['PAYLOAD_KEY'].encode())))"
        assert content.count(old)==1
        content=content.replace(old,new).replace('keychain add-certificates\n','keychain add-certificates --certificate-password @env:PAYLOAD_KEY\n')
    script.write_bytes(content.encode())
    LOGS.mkdir(exist_ok=True)
    with (LOGS/(stage+'.log')).open('wb') as output:
        child=subprocess.Popen(['bash','ci/run_sealed_candidate.sh',stage],cwd=SOURCE,stdout=output,stderr=subprocess.STDOUT)
        elapsed=0
        while True:
            try:
                code=child.wait(timeout=120)
                break
            except subprocess.TimeoutExpired:
                elapsed+=2
                print(stage+': still running ('+str(elapsed)+' minutes)',flush=True)
                try:checkpoint(stage,elapsed)
                except Exception:print('Encrypted checkpoint unavailable; primary task continues.',flush=True)
    print(stage+': '+('passed' if code==0 else 'failed; details are encrypted'))
    raise SystemExit(code)
def checkpoint(stage,elapsed):
    if not os.environ.get('GH_TOKEN'):return
    buffer=io.BytesIO()
    with zipfile.ZipFile(buffer,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=3) as archive:
        for folder,prefix in [(LOGS,'logs'),(SOURCE/'ios-evidence','evidence')]:
            if folder.exists():
                for file in folder.rglob('*'):
                    if file.is_file() and file.stat().st_size<20000000:
                        archive.writestr(prefix+'/'+file.relative_to(folder).as_posix(),file.read_bytes())
    nonce=os.urandom(12)
    target=ROOT/'encrypted-checkpoint.bin'
    target.write_bytes(b'MOBILER1'+nonce+cipher().encrypt(nonce,buffer.getvalue(),b'mobile-ci-result-v1'))
    tag='checkpoint-'+os.environ['GITHUB_RUN_ID']+'-'+stage+'-'+str(elapsed)
    result=subprocess.run(['gh','release','create',tag,str(target),'--repo',os.environ['GITHUB_REPOSITORY'],'--target',os.environ['GITHUB_SHA'],'--title','Encrypted owner build checkpoint','--notes','Authenticated encrypted owner diagnostics.'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=90)
    print('Encrypted checkpoint '+('saved.' if result.returncode==0 else 'not saved.'),flush=True)

def package():
    buffer=io.BytesIO()
    with zipfile.ZipFile(buffer,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=3) as archive:
        for folder,prefix in [(LOGS,'logs'),(SOURCE/'ios-evidence','evidence'),(SOURCE/'build/ios/ipa','ipa')]:
            if folder.exists():
                for file in folder.rglob('*'):
                    if file.is_file():archive.write(file,prefix+'/'+file.relative_to(folder).as_posix())
        metadata=SOURCE/'ci/candidate-metadata.json'
        if metadata.exists():archive.write(metadata,'candidate-metadata.json')
    nonce=os.urandom(12)
    (ROOT/'encrypted-result.bin').write_bytes(b'MOBILER1'+nonce+cipher().encrypt(nonce,buffer.getvalue(),b'mobile-ci-result-v1'))
    print('Authenticated encrypted owner result prepared.')
if __name__=='__main__':
    if sys.argv[1]=='init':initialize()
    elif sys.argv[1]=='package':package()
    else:run(sys.argv[1])
