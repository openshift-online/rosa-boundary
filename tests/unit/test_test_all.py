"""Offline regression coverage for the exhaustive local test runner."""

import importlib.util
import json
from pathlib import Path
import sys
from unittest.mock import patch


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
        self.results.append({"name": name, "passed": ok, "log": str(log)})
        return ok

    monkeypatch.setattr(runner_module.Runner, "run", fake_run)
    monkeypatch.setattr(runner_module, "source_files", lambda: [])
    monkeypatch.setattr(runner_module.tempfile, "mkdtemp", lambda **kwargs: str(artifacts))
    monkeypatch.setattr(runner_module, "terraform_checks", lambda runner, files: runner.problem("terraform", "fixture failure"))
    monkeypatch.setattr(runner_module, "localstack_check", lambda runner, allow: runner.problem("localstack", "fixture failure"))
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


def test_junit_skips_fail_unless_explicitly_allowed(tmp_path):
    report = tmp_path / "report.xml"
    report.write_text('<testsuites><testsuite><testcase/><testcase><skipped message="executor unavailable"/></testcase></testsuite></testsuites>')
    assert not runner_module.junit_status(report)[0]
    assert runner_module.junit_status(report, allow_skips=True)[0]
    report.write_text('<testsuites><testsuite/></testsuites>')
    assert not runner_module.junit_status(report, allow_skips=True)[0]


def test_remote_localstack_endpoint_is_rejected(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALSTACK_ENDPOINT", "https://aws.example.com")
    runner = runner_module.Runner(tmp_path)
    with patch("check_ready.urllib.request.build_opener") as request:
        runner_module.localstack_check(runner, False)
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
