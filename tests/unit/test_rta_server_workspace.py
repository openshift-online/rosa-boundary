"""Every managed Boundary Region must receive the shared TA origin."""
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
SOURCE = (ROOT / "hcp-terraform/rosa-boundary/main.tf").read_text()
TA_SOURCE = (ROOT / "hcp-terraform/rosa-trusted-actions/main.tf").read_text()
# terraform fmt keeps workspace declarations/closing braces at four spaces.
WORKSPACES = dict(re.findall(r"^    ([\w-]+) = \{\n(.*?)^    \}", SOURCE, re.M | re.S))
REGIONAL = {
    name: body for name, body in WORKSPACES.items()
    if re.search(r'working_directory\s*=\s*"deploy/regional"', body)
}


def test_all_regions_use_the_shared_origin():
    assert {
        "rosa-boundary-stage-regional",
        "rosa-boundary-stage-regional-us-west-2",
        "rosa-boundary-prod-regional-us-east-1",
        "rosa-boundary-prod-regional-us-west-2",
    } <= REGIONAL.keys()
    for name, body in REGIONAL.items():
        assert len(re.findall(r'key\s*=\s*"rta_server_url"', body)) == 1, name
        assert re.search(
            r'key\s*=\s*"rta_server_url"\s+value\s*=\s*local\.rta_server_url\b',
            body,
        ), name


def test_shared_origin_matches_the_declared_ta_staging_hostname():
    origin = re.search(r'rta_server_url\s*=\s*"([^"]+)"', SOURCE)
    assert origin
    hostnames = set(re.findall(
        r'key\s*=\s*"internal_fqdn"\s+value\s*=\s*"([^"]+)"', TA_SOURCE))
    assert len(hostnames) == 1
    assert origin[1] == "https://" + hostnames.pop()


def test_no_credential_or_timeout_overrides_are_added():
    for name, body in REGIONAL.items():
        assert not re.search(r'key\s*=\s*"(?:OCM_CONFIG|OCM_KEYRING|RTA_TIMEOUT)"', body), name
