#!/usr/bin/env python3
"""Fixed-source SRE installer. Verification dependencies remain in builder stages."""
import argparse
import hashlib
import json
import os
import pwd
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import urllib.parse
import urllib.request
import zipfile

TOOLS = ('ocm', 'ocm-backplane', 'osdctl', 'yq', 'oc', 'aws')
SIGNERS = {'aws': 'FB5DB77FD5C118B80511ADA8A6310ACC4672475C',
           'oc': '567E347AD0044ADE55BA8A5F199E2F91FD431D51'}
REPOS = {'ocm': 'openshift-online/ocm-cli', 'ocm-backplane': 'openshift/backplane-cli',
         'osdctl': 'openshift/osdctl', 'yq': 'mikefarah/yq'}


def pin_version(tool, pin):
    pattern = r'v\d+\.\d+\.\d+' if tool in REPOS else r'\d+\.\d+\.\d+'
    if not re.fullmatch(pattern, pin):
        raise ValueError('invalid exact version')
    version = pin.removeprefix('v')
    if (tool == 'aws' and not version.startswith('2.')) or (tool == 'yq' and not version.startswith('4.')) or (tool == 'oc' and not version.startswith('4.')):
        raise ValueError('unsupported major')
    return version


def checksum(text, name):
    matches = []
    for line in text.splitlines():
        match = re.fullmatch(r'([0-9a-fA-F]{64}) [ *](.+)', line)
        if match and match[2] == name:
            matches.append(match[1].lower())
    if len(matches) != 1:
        raise ValueError('missing, malformed or duplicate SHA256')
    return matches[0]


def safe_path(name):
    p = PurePosixPath(name)
    if not name or '\\' in name or '\x00' in name or p.is_absolute() or '..' in p.parts:
        raise ValueError('unsafe archive path')
    return p


def extract_binary(archive, name, destination):
    with tarfile.open(archive, 'r:gz') as tar:
        members = tar.getmembers()
        found = []
        seen = set()
        for member in members:
            path = safe_path(member.name)
            # OpenShift ships kubectl as a hardlink to oc. Never extract it;
            # allow only this exact inert alias, not arbitrary archive links.
            ignored_oc_alias = (name == 'oc' and member.name == 'kubectl'
                                and member.islnk() and member.linkname == 'oc')
            if str(path) in seen or not (member.isfile() or member.isdir() or ignored_oc_alias):
                raise ValueError('duplicate or unsafe tar member')
            seen.add(str(path))
            if str(path) == name and member.isfile():
                found.append(member)
        if len(found) != 1 or found[0].size > 512 * 1024 * 1024:
            raise ValueError('missing, duplicate or oversized executable')
        with tar.extractfile(found[0]) as src, open(destination, 'wb') as dst:
            shutil.copyfileobj(src, dst)
    os.chmod(destination, 0o755)


def extract_aws(archive, destination):
    with zipfile.ZipFile(archive) as zipf:
        entries = zipf.infolist()
        seen = set()
        total = 0
        for entry in entries:
            path = safe_path(entry.filename)
            mode = entry.external_attr >> 16
            kind = stat.S_IFMT(mode)
            if str(path) in seen or kind not in (0, stat.S_IFREG, stat.S_IFDIR):
                raise ValueError('duplicate or unsafe ZIP member')
            seen.add(str(path))
            if path.parts[0] != 'aws':
                raise ValueError('unexpected AWS archive root')
            total += entry.file_size
        if total > 2 * 1024**3:
            raise ValueError('oversized ZIP')
        # Validate the entire archive before writing only the distribution.
        for entry in entries:
            path = safe_path(entry.filename)
            if path.parts[:2] == ('aws', 'dist') and len(path.parts) >= 3:
                target = destination.joinpath(*path.parts[2:])
            else:
                continue
            if entry.is_dir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with zipf.open(entry) as src, target.open('wb') as dst:
                    shutil.copyfileobj(src, dst)
                target.chmod(0o755 if (entry.external_attr >> 16) & 0o111 else 0o644)
    if not (destination / 'aws').is_file():
        raise ValueError('AWS distribution missing executable')


class HTTPSRedirect(urllib.request.HTTPRedirectHandler):
    """Follow mirror/CDN redirects using urllib's loop limits, without TLS downgrade."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        target = urllib.parse.urlsplit(newurl)
        if target.scheme != 'https' or not target.hostname or target.username is not None or target.password is not None:
            raise ValueError('download redirect requires HTTPS without URL credentials')
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def download(url, destination):
    # Public oc/AWS downloads carry no GitHub auth. Mirrors may redirect across
    # hosts; pinned signatures/checksums still verify the resulting bytes.
    opener = urllib.request.build_opener(HTTPSRedirect())
    with opener.open(url, timeout=120) as response, destination.open('wb') as out:
        size = 0
        while True:
            chunk = response.read(1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            if size > 1024**3:
                raise ValueError('download too large')
            out.write(chunk)


def verify_signature(tool, data, signature, key_dir, output=None):
    with tempfile.TemporaryDirectory() as home:
        os.chmod(home, 0o700)
        key = key_dir / ('aws-cli.asc' if tool == 'aws' else 'redhat-release-2.asc')
        base = ['gpg', '--batch', '--no-options', '--homedir', home]
        subprocess.run(base + ['--import', str(key)], check=True, capture_output=True)
        args = ['--status-fd', '1']
        args += ['--output', str(output), '--decrypt', str(data)] if output else ['--verify', str(signature), str(data)]
        result = subprocess.run(base + args, check=True, capture_output=True, text=True)
        valid = [line.split() for line in result.stdout.splitlines() if line.startswith('[GNUPG:] VALIDSIG ')]
        # VALIDSIG field 2 is the signing key, optional field 11 its primary.
        if len(valid) != 1 or (valid[0][11] if len(valid[0]) > 11 else valid[0][2]) != SIGNERS[tool]:
            raise ValueError('unexpected signature identity')
        if any(marker in result.stdout for marker in ('BADSIG', 'ERRSIG', 'EXPKEYSIG', 'REVKEYSIG', 'EXPSIG')):
            raise ValueError('unacceptable signature status')


def actual_version(tool, executable):
    commands = {'ocm': ['version'], 'ocm-backplane': ['version'],
                'osdctl': ['version', '--skip-version-check'],
                'yq': ['--version'], 'oc': ['version', '--client'], 'aws': ['--version']}
    with tempfile.TemporaryDirectory() as home:
        command = [str(executable)] + commands[tool]
        identity = {}
        if os.getuid() == 0:
            nobody = pwd.getpwnam('nobody')
            os.chown(home, nobody.pw_uid, nobody.pw_gid)
            identity = dict(user=nobody.pw_uid, group=nobody.pw_gid, extra_groups=[])
        result = subprocess.run(command, check=True, capture_output=True,
                                text=True, timeout=30, **identity, env={'HOME': home, 'PATH': '/usr/local/bin:/usr/bin:/bin', 'LANG': 'C',
                                    'HTTP_PROXY': 'http://127.0.0.1:9', 'HTTPS_PROXY': 'http://127.0.0.1:9'})
    output = result.stdout + result.stderr
    if tool == 'osdctl':
        # osdctl's version subcommand emits JSON including a separate latest
        # field, even with --skip-version-check. Never use latest as evidence.
        value = json.loads(result.stdout)['version']
        if not isinstance(value, str) or not re.fullmatch(r'v?\d+\.\d+\.\d+', value):
            raise ValueError('invalid osdctl version JSON')
        return value.removeprefix('v')
    patterns = {'aws': r'aws-cli/(\d+\.\d+\.\d+)(?![\d.\w+-])',
                'yq': r'version v?(\d+\.\d+\.\d+)(?![\d.\w+-])',
                'oc': r'Client Version: v?(\d+\.\d+\.\d+)(?![\d.\w+-])'}
    pattern = patterns.get(tool, r'(?<![\d.])v?(\d+\.\d+\.\d+)(?![\d.\w+-])')
    versions = re.findall(pattern, output)
    if len(versions) != 1:
        raise ValueError(f'{tool}: ambiguous or unrecognized version output')
    return versions[0]


def require_version(tool, pin, actual):
    if pin_version(tool, pin) != actual:
        raise ValueError(f'{tool}: expected {pin}, got {actual}')


def install(tool, pin, arch, output, keys):
    version = pin_version(tool, pin)
    if arch not in ('amd64', 'arm64'):
        raise ValueError('unsupported architecture')
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        signer = None
        if tool in REPOS:
            goarch = 'x86_64' if arch == 'amd64' else 'arm64'
            names = {'ocm': f'ocm-linux-{arch}', 'ocm-backplane': f'ocm-backplane_{version}_Linux_{goarch}.tar.gz',
                     'osdctl': f'osdctl_{version}_Linux_{goarch}.tar.gz',
                     'yq': f'yq_linux_{arch}'}
            name = names[tool]
            sums = {'ocm': name + '.sha256', 'osdctl': 'sha256sum.txt', 'yq': 'checksums-bsd'}
            source = f'https://api.github.com/repos/{REPOS[tool]}/releases/tags/{pin}'
            subprocess.run(['github_dl', 'download', '--url', source,
                            '--checksum_file', sums.get(tool, 'checksums.txt'),
                            '--exact_asset', name], cwd=work, check=True)
            archive = work / name
        elif tool == 'aws':
            awsarch = 'x86_64' if arch == 'amd64' else 'aarch64'
            source = f'https://awscli.amazonaws.com/awscli-exe-linux-{awsarch}-{version}.zip'
            archive = work / 'aws.zip'
            signature = work / 'aws.sig'
            download(source, archive)
            download(source + '.sig', signature)
            verify_signature(tool, archive, signature, keys)
            signer = SIGNERS[tool]
        else:
            root = f'https://mirror.openshift.com/pub/openshift-v4/{arch}/clients/ocp/{version}/'
            name = f'openshift-client-linux-{version}.tar.gz'
            source = root + name
            archive = work / name
            signed = work / 'checksums.gpg'
            plain = work / 'checksums.txt'
            download(root + 'sha256sum.txt.gpg', signed)
            verify_signature(tool, signed, None, keys, plain)
            download(source, archive)
            if hashlib.sha256(archive.read_bytes()).hexdigest() != checksum(plain.read_text(), name):
                raise ValueError('oc SHA256 mismatch')
            signer = SIGNERS[tool]
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        target = output / tool
        if tool == 'aws':
            target = output / 'aws_dist'
            target.mkdir()
            extract_aws(archive, target)
            target = target / 'aws'
        elif tool in ('ocm', 'yq'):
            shutil.copyfile(archive, target)
            target.chmod(0o755)
        else:
            extract_binary(archive, tool, target)
        # Do not execute downloaded artifacts here: GitHub secrets may be mounted.
        # A separate network-isolated RUN records actual versions without secrets.
        actual = None
        inventory = output / 'inventory'
        inventory.mkdir(exist_ok=True)
        (inventory / f'{tool}.json').write_text(json.dumps(dict(tool=tool, expected_pin=pin, actual_version=actual,
                    architecture=arch, source=source, sha256=digest, signature_identity=signer), indent=2) + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('tool', choices=TOOLS)
    parser.add_argument('--version', required=True)
    parser.add_argument('--arch', required=True, choices=('amd64', 'arm64'))
    parser.add_argument('--output', type=Path, default=Path('/opt'))
    parser.add_argument('--keys', type=Path, default=Path('/usr/local/share/sre-tools/keys'))
    parser.add_argument('--validate-installed', action='store_true')
    args = parser.parse_args()
    if args.validate_installed:
        from verify_sre_tools import elf_arch
        path = args.output / 'inventory' / f'{args.tool}.json'
        entry = json.loads(path.read_text())
        if entry['expected_pin'] != args.version or entry['architecture'] != args.arch:
            raise ValueError('installed artifact metadata mismatch')
        executable = args.output / ('aws_dist/aws' if args.tool == 'aws' else args.tool)
        elf_arch(executable, args.arch)
        actual = actual_version(args.tool, executable)
        require_version(args.tool, args.version, actual)
        entry['actual_version'] = actual
        path.write_text(json.dumps(entry, indent=2) + '\n')
    else:
        install(args.tool, args.version, args.arch, args.output, args.keys)


if __name__ == '__main__':
    main()
