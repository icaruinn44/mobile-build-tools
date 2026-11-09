"""Upload the exact, already verified signed IPA; never rebuild it."""
import base64,hashlib,io,json,os,plistlib,subprocess,urllib.request,zipfile
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

root=Path(__file__).resolve().parent
evidence=root/'ios-evidence';evidence.mkdir(exist_ok=True)
key=AESGCM(base64.b64decode(os.environ['PAYLOAD_KEY']))
raw=urllib.request.urlopen('https://github.com/icaruinn44/mobile-build-tools/releases/download/result-42544245576/encrypted-result.bin',timeout=180).read()
assert raw[:8]==b'MOBILER1' and hashlib.sha256(raw).hexdigest()=='47e8fd4862e27171b682d7b81ed2c6a10c5c0cbe9a2abcc760e6a492e2c6c09a'
plain=key.decrypt(raw[8:20],raw[20:],b'mobile-ci-result-v1')
with zipfile.ZipFile(io.BytesIO(plain)) as archive:
 names=[name for name in archive.namelist() if name.startswith('ipa/') and name.endswith('.ipa')]
 assert len(names)==1
 verified=json.loads(archive.read('evidence/ipa-verification.json'))
 assert verified['bundleId']=='com.mistikdevelopment.mistik' and verified['version']=='6.1.4' and verified['build']=='68'
 assert verified['codesignVerified'] and verified['reviewCredentialsAbsent'] and verified['appAttest']=='production'
 ipa=archive.read(names[0]);assert hashlib.sha256(ipa).hexdigest()==verified['sha256']=='44fce9b62c4909cc5466f8874dadb4aba5823c3b90c68616f8864ee822f27417'
 file=root/'Mistik-6.1.4-68.ipa';file.write_bytes(ipa)
with zipfile.ZipFile(file) as archive:
 infos=[n for n in archive.namelist() if n.startswith('Payload/') and n.count('/')==2 and n.endswith('/Info.plist')]
 assert len(infos)==1
 info=plistlib.loads(archive.read(infos[0]));assert info['CFBundleIdentifier']==verified['bundleId'] and info['CFBundleVersion']=='68' and info['CFBundleShortVersionString']=='6.1.4'
assert info['ITSAppUsesNonExemptEncryption'] is False
(evidence/'ipa-verification.json').write_text(json.dumps(verified,indent=2))
keys=Path.home()/'.private_keys';keys.mkdir(exist_ok=True)
private=keys/('AuthKey_'+os.environ['ASC_KEY_ID']+'.p8')
code=1
try:
 private.write_bytes(base64.b64decode(os.environ['ASC_KEY_BASE64']));private.chmod(0o600)
 with (evidence/'apple-upload.txt').open('wb') as log:
  result=subprocess.run(['xcrun','altool','--upload-app','--type','ios','--file',str(file),'--apiKey',os.environ['ASC_KEY_ID'],'--apiIssuer',os.environ['ASC_ISSUER_ID']],stdout=log,stderr=subprocess.STDOUT,timeout=1200)
 code=result.returncode
finally:
 private.unlink(missing_ok=True);file.unlink(missing_ok=True)
 (evidence/'upload-outcome.json').write_text(json.dumps({'exitCode':code,'ipaSha256':verified['sha256'],'rebuilt':False},indent=2))
 buffer=io.BytesIO()
 with zipfile.ZipFile(buffer,'w',zipfile.ZIP_DEFLATED) as archive:
  for path in evidence.iterdir():archive.write(path,'evidence/'+path.name)
 nonce=os.urandom(12)
 (root/'encrypted-result.bin').write_bytes(b'MOBILER1'+nonce+key.encrypt(nonce,buffer.getvalue(),b'mobile-ci-result-v1'))
print('Exact verified IPA upload '+('completed.' if code==0 else 'failed; private diagnostics encrypted.'))
raise SystemExit(code)
