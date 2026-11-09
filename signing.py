"""Import existing owner signing material using macOS-compatible PEM sequence format."""
from pathlib import Path
from datetime import datetime, timezone
import base64, json, os, plistlib, subprocess
from cryptography.hazmat.primitives.serialization import pkcs12, Encoding, PrivateFormat, NoEncryption
from cryptography.x509.oid import NameOID

def run(*args): subprocess.run(args,check=True)
key,cert,_=pkcs12.load_key_and_certificates(base64.b64decode(os.environ['IOS_CERTIFICATE_BASE64']),None)
assert key is not None and cert is not None
assert cert.not_valid_after_utc>datetime.now(timezone.utc)
assert cert.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)[0].value==os.environ['APPLE_TEAM_ID']
raw=Path('ci/candidate-profile.mobileprovision').read_bytes()
profile=plistlib.loads(subprocess.check_output(['security','cms','-D'],input=raw))
meta=json.loads(Path('ci/candidate-metadata.json').read_text())
assert profile['UUID']==meta['profileUuid'] and cert.public_bytes(Encoding.DER) in profile['DeveloperCertificates']
assert profile['TeamIdentifier']==[os.environ['APPLE_TEAM_ID']]
assert profile['Entitlements']['application-identifier']==os.environ['APPLE_TEAM_ID']+'.'+os.environ['BUNDLE_ID']
assert profile['Entitlements']['aps-environment']=='production'
assert profile['Entitlements']['com.apple.developer.applesignin']==['Default']
run('keychain','initialize')
for folder in ['Certificates','Provisioning Profiles']:
    (Path.home()/'Library/MobileDevice'/folder).mkdir(parents=True,exist_ok=True)
# codemagic-cli-tools supports PEM-sequence fallback for .p12 files, avoiding
# the macOS incompatibility with cryptography's unencrypted SHA-256-MAC PFX.
cert_path=Path.home()/'Library/MobileDevice/Certificates/distribution.p12'
cert_path.write_bytes(cert.public_bytes(Encoding.PEM)+key.private_bytes(Encoding.PEM,PrivateFormat.TraditionalOpenSSL,NoEncryption()))
cert_path.chmod(0o600)
(Path.home()/'Library/MobileDevice/Provisioning Profiles'/(profile['UUID']+'.mobileprovision')).write_bytes(raw)
run('keychain','add-certificates')
run('xcode-project','use-profiles','--project','ios/Runner.xcodeproj')
options=plistlib.loads((Path.home()/'export_options.plist').read_bytes())
assert options['teamID']==os.environ['APPLE_TEAM_ID']
assert options['provisioningProfiles'][os.environ['BUNDLE_ID']] in [profile['UUID'],profile['Name']]
print('Distribution identity, provisioning profile and export settings verified.')
