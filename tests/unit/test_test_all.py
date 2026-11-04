"""Offline regression coverage for the exhaustive local test runner."""

import importlib.util
import json
from pathlib import Path
import sys
from unittest.mock import patch

import pytest


SPEC = importlib.util.spec_from_file_location("test_all_runner", Path(__file__).resolve().parents[2] / "scripts/test_all.py")
runner_module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner_module)


def test_runner_continues_after_failure_and_preserves_full_output(tmp_path):
    runner = runner_module.Runner(tmp_path)
    assert not runner.run("bad", [sys.executable, "-c", "print('complete diagnostic'); raise SystemExit(7)"])
    assert runner.run("good", [sys.executable, "-c", "print('next check ran')"])
    assert len(runner.results) == 2
    assert "complete diagnostic" in Path(runner.results[0]["log"]).read_text()


def test_full_entrypoint_attempts_all_gates_after_failure(tmp_path, monkeypatch):
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    commands = []

    def fake_run(self, name, command, **kwargs):
        commands.append((name, command))
        log = artifacts / f"{name}.log"
        log.write_text("")
        ok = name != "test-coverage"
        self.results.append({"name": name, "status": "PASS" if ok else "FAIL", "passed": ok, "log": str(log)})
        return ok

    monkeypatch.setattr(runner_module.Runner, "run", fake_run)
    monkeypatch.setattr(runner_module, "source_files", lambda: [])
    monkeypatch.setattr(runner_module.tempfile, "mkdtemp", lambda **kwargs: str(artifacts))
    monkeypatch.setattr(runner_module, "terraform_checks", lambda runner, files: runner.problem("terraform", "fixture failure"))
    monkeypatch.setattr(runner_module, "localstack_check", lambda runner: runner.problem("localstack", "fixture failure"))
    monkeypatch.setattr(sys, "argv", ["test_all.py"])
    assert runner_module.main() == 1
    names = [name for name, _ in commands]
    assert names[-1] == "pre-commit"
    assert "python-unit" in names
    assert "live-tooling-unit" in names
    assert "container-build-both-architectures" in names
    assert "lambda-container-build" in names
    assert "shellcheck-all" in names
    assert "python-syntax" in names
    summary = json.loads((artifacts / "summary.json").read_text())
    assert any(not result["passed"] for result in summary)


def test_missing_executable_is_a_recorded_failure(tmp_path):
    runner = runner_module.Runner(tmp_path)
    assert not runner.run("missing", ["/nonexistent/rosa-test-tool"])
    assert not runner.results[0]["passed"]


@pytest.mark.parametrize("cases,status", [
    ('<testcase/>', 'PASS'),
    ('<testcase/><testcase><skipped message="executor unavailable"/></testcase>', 'INCOMPLETE'),
    ('<testcase><skipped/></testcase>', 'INCOMPLETE'),
    ('', 'FAIL'),
    ('<testcase><failure/></testcase><testcase><skipped/></testcase>', 'FAIL'),
    ('<testcase><error/></testcase>', 'FAIL'),
])
def test_junit_distinguishes_failures_and_incomplete_coverage(tmp_path, cases, status):
    report = tmp_path / "report.xml"
    report.write_text(f'<testsuites><testsuite>{cases}</testsuite></testsuites>')
    assert runner_module.junit_status(report)[0] == status


def test_remote_localstack_endpoint_is_rejected(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALSTACK_ENDPOINT", "https://aws.example.com")
    runner = runner_module.Runner(tmp_path)
    with patch("check_ready.urllib.request.build_opener") as request:
        runner_module.localstack_check(runner)
    request.assert_not_called()
    assert not runner.results[0]["passed"]


def test_terraform_failure_blocks_module_tests_but_attempts_next_root(tmp_path):
    runner = runner_module.Runner(tmp_path)
    with patch.object(runner_module, "ROOT", tmp_path):
        for module in ("deploy/account", "deploy/regional"):
            directory = tmp_path / module
            directory.mkdir(parents=True)
            (directory / "main.tf").write_text('terraform {}')
        with patch.object(runner, "run", return_value=False) as run:
            runner_module.terraform_checks(runner, ["deploy/account/main.tf", "deploy/regional/main.tf"])
    assert run.call_count == 2
    for call in run.call_args_list:
        assert call.args[1] == ["terraform", "init", "-backend=false", "-input=false", "-no-color"]
        assert not call.kwargs["cwd"].exists()  # disposable directory cleaned up


def test_terraform_tests_without_mocked_aws_are_not_executed(tmp_path):
    module = tmp_path / "deploy/account"
    (module / "tests").mkdir(parents=True)
    (module / "main.tf").write_text('terraform {}')
    (module / "tests/unsafe.tftest.hcl").write_text('run "unsafe" { command = apply }')
    runner = runner_module.Runner(tmp_path)
    with patch.object(runner_module, "ROOT", tmp_path), patch.object(runner, "run", return_value=True) as run:
        runner_module.terraform_checks(runner, ["deploy/account/main.tf", "deploy/account/tests/unsafe.tftest.hcl"])
    assert run.call_count == 2  # init and validate only
    assert "refusing" in runner.results[0]["detail"]


@pytest.mark.parametrize("flags,coverage,failed,expected", [
    ([], 'PASS', False, 0),
    ([], 'INCOMPLETE', False, 0),
    (['--require-complete'], 'INCOMPLETE', False, 1),
    (['--require-complete'], 'PASS', False, 0),
    ([], 'INCOMPLETE', True, 1),
    (['--require-complete'], 'INCOMPLETE', True, 1),
    ([], 'FAIL', False, 1),
])
def test_completion_policy_preserves_status_and_real_failures(tmp_path, monkeypatch, capsys, flags, coverage, failed, expected):
    def fake_run(self, name, command, **kwargs):
        log = tmp_path / f'{name}.log'
        log.write_text('')
        ok = not (failed and name == 'test-coverage')
        self.results.append({'name': name, 'status': 'PASS' if ok else 'FAIL', 'passed': ok, 'log': str(log)})
        return ok

    monkeypatch.setattr(runner_module.Runner, 'run', fake_run)
    monkeypatch.setattr(runner_module, 'source_files', lambda: [])
    monkeypatch.setattr(runner_module.tempfile, 'mkdtemp', lambda **kwargs: str(tmp_path))
    monkeypatch.setattr(runner_module, 'terraform_checks', lambda runner, files: None)
    monkeypatch.setattr(runner_module, 'localstack_check', lambda runner: runner.report('localstack-coverage', coverage, 'fixture coverage detail'))
    monkeypatch.setattr(sys, 'argv', ['test_all.py', *flags])
    assert runner_module.main() == expected
    summary = json.loads((tmp_path / 'summary.json').read_text())
    result = next(item for item in summary if item['name'] == 'localstack-coverage')
    assert result['status'] == coverage
    assert result['passed'] == (coverage == 'PASS')
    output = capsys.readouterr().out
    assert f'{coverage} localstack-coverage: fixture coverage detail' in output
    if coverage == 'INCOMPLETE':
        assert 'NOT verified' in output
        assert 'FAIL localstack-coverage' not in output


@pytest.mark.parametrize('contents', [None, '<broken', '<testsuites><testsuite/></testsuites>'])
def test_missing_invalid_or_empty_junit_is_always_failure(tmp_path, monkeypatch, contents):
    runner = runner_module.Runner(tmp_path)
    monkeypatch.setattr(runner_module, 'require_ready', lambda endpoint: None)
    monkeypatch.setattr(runner, 'run', lambda *args, **kwargs: True)
    if contents is not None:
        (tmp_path / 'localstack.xml').write_text(contents)
    runner_module.localstack_check(runner)
    assert runner.results[-1]['status'] == 'FAIL'


def test_localstack_skips_are_recorded_as_incomplete(tmp_path, monkeypatch):
    runner = runner_module.Runner(tmp_path)
    monkeypatch.setattr(runner_module, 'require_ready', lambda endpoint: None)
    monkeypatch.setattr(runner, 'run', lambda *args, **kwargs: True)
    (tmp_path / 'localstack.xml').write_text('<testsuites><testsuite><testcase/><testcase><skipped/></testcase></testsuite></testsuites>')
    runner_module.localstack_check(runner)
    assert runner.results[-1]['status'] == 'INCOMPLETE'
    assert '1/2 tests skipped' in runner.results[-1]['detail']


def test_removed_allow_skips_option_is_rejected(monkeypatch, capsys):
    monkeypatch.setattr(sys, 'argv', ['test_all.py', '--allow-skips'])
    with pytest.raises(SystemExit) as error:
        runner_module.main()
    assert error.value.code == 2
    assert 'unrecognized arguments: --allow-skips' in capsys.readouterr().err
