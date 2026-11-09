"""Verify the exported distribution app, independently of the archive copy."""
from pathlib import Path
import json, os, plistlib, subprocess, tempfile, zipfile

ipa, = Path('build/ios/ipa').glob('*.ipa')
with tempfile.TemporaryDirectory(prefix='owner-export-verification-') as folder:
    target=Path(folder)
    with zipfile.ZipFile(ipa) as archive:
        for name in archive.namelist():
            assert (target/name).resolve().is_relative_to(target.resolve())
        archive.extractall(target)
    app, = (target/'Payload').glob('*.app')
    subprocess.run(['codesign','--verify','--deep','--strict',str(app)],check=True)
    info=plistlib.loads((app/'Info.plist').read_bytes())
    assert info['CFBundleIdentifier']==os.environ['BUNDLE_ID']
    assert info['CFBundleShortVersionString']==os.environ['BUILD_NAME']
    assert info['CFBundleVersion']==os.environ['BUILD_NUMBER']
    entitlements=plistlib.loads(subprocess.check_output(['codesign','-d','--entitlements',':-',str(app)],stderr=subprocess.DEVNULL))
    assert entitlements['application-identifier']==os.environ['APPLE_TEAM_ID']+'.'+os.environ['BUNDLE_ID']
    assert entitlements['com.apple.developer.team-identifier']==os.environ['APPLE_TEAM_ID']
    assert not entitlements['get-task-allow']
    summary=Path('ios-evidence/ipa-verification.json')
    result=json.loads(summary.read_text())
    result.update(exportedIpaCodesignVerified=True,exportedIpaBundleVersionTeamVerified=True)
    summary.write_text(json.dumps(result,indent=2))
print('Exported IPA code signature, application identity, version and team verified.')
