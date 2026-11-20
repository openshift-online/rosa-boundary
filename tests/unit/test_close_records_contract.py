"""Pin the close-record contract shared by two separately packaged Lambdas.

The authenticated request/status handler ships with the create-investigation
artifact; the finalizer ships with the reaper. They are built and deployed
independently, so each declares the contract for itself. If those declarations
ever drift, a request would be written where the reaper does not look, or a
status the CLI cannot read — silently. These tests make that drift a test
failure instead.
"""

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
REAPER = ROOT / 'lambda' / 'reap-investigations'
CREATE = ROOT / 'lambda' / 'create-investigation'


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


records = load(REAPER / 'boundary_close_records.py', 'contract_records')
requests = load(CREATE / 'close_requests.py', 'contract_requests')

CLUSTER = 'cluster-1'
INVESTIGATION = 'inv-1'
TOKEN = '11111111-2222-4333-8444-555555555555'
TASK_ID = 'a' * 32

SHARED_CONSTANTS = [
    'CONTROL_PREFIX',
    'REQUEST_SCHEMA_VERSION',
    'INTENT_SCHEMA_VERSION',
    'KIND_REQUEST',
    'KIND_INTENT',
    'KIND_STATUS',
    'TAG_SEAL',
    'TAG_MANAGED',
    'TAG_REQUEST',
    'MANAGED_BY',
    'MANAGED_BY_LAMBDA',
    'STOP_NONE',
    'STOP_SESSION_TASK',
    'STOP_INVESTIGATION',
    'STOP_SCOPES',
    'TRIGGERS',
    'STATE_ACTIVE',
    'STATE_IDLE',
    'STATE_UNKNOWN',
    'STATUS_ACCEPTED',
    'STATUS_WAITING_FOR_TASKS',
    'STATUS_VERIFYING',
    'STATUS_RETAINED',
    'STATUS_CLEANUP_INCOMPLETE',
    'STATUS_COMPLETED',
    'TERMINAL_STATUSES',
    'MAX_RECORD_BYTES',
]


@pytest.mark.parametrize('name', SHARED_CONSTANTS)
def test_shared_constants_agree(name):
    assert getattr(records, name) == getattr(requests, name), name


REQUESTED_AT = '2026-03-04T05:06:07+00:00'


@pytest.mark.parametrize('builder,args', [
    ('requests_prefix', (CLUSTER, INVESTIGATION)),
    ('request_key', (CLUSTER, INVESTIGATION, TOKEN, REQUESTED_AT)),
    ('intents_prefix', (CLUSTER, INVESTIGATION)),
    ('intent_key', (CLUSTER, INVESTIGATION, TASK_ID)),
    ('status_key', (CLUSTER, INVESTIGATION)),
    ('request_stamp', (REQUESTED_AT,)),
    ('parse_request_filename', (f'20260304T050607Z-{TOKEN}.json',)),
])
def test_key_builders_agree(builder, args):
    assert getattr(records, builder)(*args) == getattr(requests, builder)(*args)


@pytest.mark.parametrize('pattern', [
    'REQUEST_TOKEN_PATTERN', 'IDENTIFIER_PATTERN', 'ACCESS_POINT_PATTERN', 'TASK_ID_PATTERN',
    'REQUEST_FILENAME',
])
def test_validation_patterns_agree(pattern):
    assert getattr(records, pattern).pattern == getattr(requests, pattern).pattern


def test_both_sides_encode_records_identically():
    record = {'b': 2, 'a': 1, 'kind': records.KIND_REQUEST}
    assert records.encode_record(record) == requests.encode_record(record)


def test_a_request_the_handler_writes_is_one_the_reaper_accepts():
    """The whole point of the contract: a real request round-trips."""
    record = {
        'schema_version': requests.REQUEST_SCHEMA_VERSION,
        'kind': requests.KIND_REQUEST,
        'request_token': TOKEN,
        'cluster_id': CLUSTER,
        'investigation_id': INVESTIGATION,
        'access_point_id': 'fsap-00000000',
        'requester_sub': 'sre-a',
        'stop_scope': requests.STOP_SESSION_TASK,
        'stop_task_ids': [TASK_ID],
        'trigger': 'auto_close',
        'requested_at': REQUESTED_AT,
    }
    body = requests.encode_record(record)
    decoded = records.decode_record(body, records.KIND_REQUEST)
    assert records.validate_request(decoded) == record
    # The key the handler writes is the key the finalizer parses.
    key = requests.request_key(CLUSTER, INVESTIGATION, TOKEN, REQUESTED_AT)
    assert records.parse_request_filename(key.rsplit('/', 1)[-1]) == (
        records.request_stamp(REQUESTED_AT), TOKEN)


def test_an_intent_the_handler_writes_is_one_the_reaper_accepts():
    record = {
        'schema_version': requests.INTENT_SCHEMA_VERSION,
        'kind': requests.KIND_INTENT,
        'cluster_id': CLUSTER,
        'investigation_id': INVESTIGATION,
        'access_point_id': 'fsap-00000000',
        'task_id': TASK_ID,
        'requester_sub': 'sre-a',
        'stop_scope': requests.STOP_SESSION_TASK,
        'created_at': '2026-01-01T00:00:00+00:00',
        'cancelled': False,
    }
    decoded = records.decode_record(requests.encode_record(record), records.KIND_INTENT)
    assert records.validate_intent(decoded) == record


def test_the_scheduled_trigger_is_not_something_a_client_may_submit():
    assert records.TRIGGER_STALE not in requests.TRIGGERS
    assert records.TRIGGER_STALE not in records.TRIGGERS


def test_control_records_live_outside_any_reachable_workspace_path():
    """No cluster or investigation ID can name the control prefix."""
    for module in (records, requests):
        assert not module.IDENTIFIER_PATTERN.match(module.CONTROL_PREFIX)
