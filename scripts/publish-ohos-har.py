#!/usr/bin/env python3
"""Publish once; success requires downloading and verifying the registry bytes."""
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

spec = importlib.util.spec_from_file_location('har', Path(__file__).with_name('verify-ohos-har.py'))
har = importlib.util.module_from_spec(spec)
spec.loader.exec_module(har)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, new_url):
        raise ValueError('Refusing registry redirect with authorization')


def main():
    archive, sidecar = map(Path, sys.argv[1:])
    version = os.environ['HAR_PACKAGE_VERSION']
    sha = os.environ['GITHUB_SHA']
    local = har.verify(archive, sha, version, sidecar)
    registry = os.environ['CODEARTS_OHPM_REGISTRY'].rstrip('/') + '/'
    config = os.environ['CODEARTS_PRIVATE_OHPM']
    values = dict(line.strip().split('=', 1) for line in config.splitlines() if '=' in line)
    origin = urllib.parse.urlsplit(registry)
    auth_key = '//' + origin.netloc + origin.path + ':_auth'
    auth = values[auth_key].strip().strip('\"\'')
    if not auth.startswith('Basic '):
        auth = 'Basic ' + auth
    opener = urllib.request.build_opener(NoRedirect)

    def fetch(url):
        destination = urllib.parse.urlsplit(url)
        if destination.scheme != 'https' or destination.netloc != origin.netloc or not destination.path.startswith(origin.path):
            raise ValueError('Registry download is outside the authorized HTTPS registry')
        request = urllib.request.Request(url, headers={'Authorization': auth, 'Accept': 'application/json'})
        with opener.open(request, timeout=60) as response:
            return response.read()

    def distribution():
        try:
            metadata = json.loads(fetch(registry + 'rustdesk-ohrs'))
        except urllib.error.HTTPError as error:
            if error.code == 404:
                return None
            raise
        return metadata.get('versions', {}).get(version, {}).get('dist')

    dist = distribution()
    publish_result = 'already-present'
    if dist is None:
        private_config = Path.home() / '.ohpm/.ohpmrc'
        private_config.parent.mkdir(parents=True, exist_ok=True)
        # No disabled TLS verification or unrelated config is inherited.
        private_config.write_text(f'{auth_key}={auth}\npublish_registry={registry}\nstrict_ssl=true\n')
        private_config.chmod(0o600)
        try:
            try:
                completed = subprocess.run(
                    ['ohpm', 'publish', '--publish_registry', registry, str(archive)],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=300)
                publish_result = f'exit-{completed.returncode}'
            except subprocess.TimeoutExpired:
                publish_result = 'unknown-timeout'
        finally:
            private_config.unlink(missing_ok=True)
        # Never resend a timed-out/failed upload. Reconcile by immutable version.
        dist = distribution()
    if dist is None:
        raise ValueError(f'Version is not observable in registry after {publish_result}; upload was not retried')
    downloaded = fetch(dist['tarball'])
    algorithm, encoded = dist['integrity'].split('-', 1)
    if algorithm not in ('sha256', 'sha512') or base64.b64encode(hashlib.new(algorithm, downloaded).digest()).decode() != encoded:
        raise ValueError('Downloaded HAR does not match registry integrity')
    if hashlib.sha256(downloaded).hexdigest() != local['har_sha256']:
        raise ValueError('Registry version already contains different bytes; refusing publication success')
    remote_archive = archive.parent / 'registry-package.har'
    remote_archive.write_bytes(downloaded)
    har.verify(remote_archive, sha, version, sidecar)
    evidence = {
        **local,
        'registry': registry,
        'registry_integrity': dist['integrity'],
        'publication_result': publish_result,
        'download_verified': True,
        'github_run_id': os.environ['GITHUB_RUN_ID'],
    }
    (archive.parent / 'registry-verification.json').write_text(json.dumps(evidence, indent=2, sort_keys=True) + '\n')
    print(f'Verified registry bytes for rustdesk-ohrs@{version}: {local["har_sha256"]}')


if __name__ == '__main__':
    main()
