"""Tests for GUI state loading helpers."""

import os
import sys
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
os.environ.setdefault("QTWEBENGINE_DISABLE_SANDBOX", "1")

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from PySide6.QtWidgets import QApplication

from gui.app import MainWindow
from state.manager import StateManager


def test_gui_loads_advanced_state_tabs(tmp_path):
    app = QApplication.instance() or QApplication([])
    state = StateManager(str(tmp_path / "reports" / "example.com"))
    state.add_asset("domain", "domain:example.com", "example.com")
    state.add_asset("screenshot_target", "screenshot:https://example.com", "https://example.com")
    evidence_id = state.add_evidence("test_module", "json", "subject", {"ok": True})
    state.add_finding(
        title="Example Finding",
        severity="HIGH",
        confidence="FIRM",
        category="Test",
        description="Test finding.",
        evidence_refs=[evidence_id],
        risk_score=80,
    )
    run_id = state.begin_module_run("test_module", "low", 4)
    state.finish_module_run(run_id, "completed")
    state.save()
    submission_dir = state.output_dir / "submissions"
    submission_dir.mkdir()
    (submission_dir / "INDEX.md").write_text("# Index")
    (state.output_dir / "example.com_summary.json").write_text(
        '{"risk":{"max_score":80,"critical_high":1}}'
    )

    window = MainWindow()
    window.output_dir = tmp_path / "reports"
    window.output_input.setText(str(window.output_dir))
    window.target_input.setText("example.com")
    window.refresh_graph = lambda: None
    window.load_results()

    assert window.assets_value.text() == "2"
    assert window.findings_value.text() == "1"
    assert window.evidence_value.text() == "1"
    assert window.max_risk_value.text() == "80"
    assert window.evidence_table.rowCount() == 1
    assert window.submissions_table.rowCount() == 1
    assert window.modules_table.rowCount() > 0

    window.close()
    app.processEvents()


def test_gui_saves_llm_settings(tmp_path):
    app = QApplication.instance() or QApplication([])
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "llm:\n"
        "  model: \"\"\n"
        "  api_key: \"\"\n"
        "  temperature: 0.1\n"
        "  max_tokens: 2000\n"
        "api_keys: {}\n"
    )

    window = MainWindow()
    window.config_path = config_path
    window._load_settings_form()
    window.llm_model_combo.setCurrentText("ollama/llama3.1")
    window.llm_api_key_input.setText("")
    window.llm_temperature_spin.setValue(0.2)
    window.llm_max_tokens_spin.setValue(4096)
    window._save_settings_form()

    saved = config_path.read_text()
    assert "ollama/llama3.1" in saved
    assert "temperature: 0.2" in saved
    assert "max_tokens: 4096" in saved

    window.close()
    app.processEvents()


def test_gui_saves_scanner_settings(tmp_path):
    app = QApplication.instance() or QApplication([])
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "target: {}\n"
        "llm: {}\n"
        "api_keys: {}\n"
        "auth: {}\n"
        "xss: {}\n"
        "nuclei: {}\n"
        "oob: {}\n"
    )

    window = MainWindow()
    window.config_path = config_path
    window._load_settings_form()
    window.auth_bearer_input.setText("token-123")
    window.auth_cookie_input.setText("sid=abc")
    window.auth_headers_input.setPlainText("X-Test: yes\nBad header")
    window.auth_probe_backoff_spin.setValue(12)
    window.xss_browser_confirm_check.setChecked(True)
    window.xss_max_points_spin.setValue(123)
    window.xss_dalfox_timeout_spin.setValue(456)
    window.nuclei_full_cve_check.setChecked(False)
    window.fast_scan_paths_input.setPlainText("/.env\n/.git/config")
    window.fast_scan_timeout_spin.setValue(3)
    window.fast_scan_concurrency_spin.setValue(6)
    window.fast_scan_max_paths_spin.setValue(12)
    window.oob_callback_domain_input.setText("oob.example.test")
    window.oob_poll_timeout_spin.setValue(44)
    window._save_settings_form()

    saved = config_path.read_text()
    assert "bearer_token: token-123" in saved
    assert "cookie: sid=abc" in saved
    assert "X-Test: 'yes'" in saved or "X-Test: yes" in saved
    assert "max_points: 123" in saved
    assert "dalfox_timeout: 456" in saved
    assert "full_cve_on_confirmed_apex: false" in saved
    assert "/.env" in saved
    assert "/.git/config" in saved
    assert "timeout: 3" in saved
    assert "concurrency: 6" in saved
    assert "max_paths: 12" in saved
    assert "callback_domain: oob.example.test" in saved
    assert "poll_timeout: 44" in saved

    window.close()
    app.processEvents()


def test_gui_full_url_uses_hostname_output_folder(tmp_path):
    app = QApplication.instance() or QApplication([])
    window = MainWindow()
    window.output_dir = tmp_path / "reports"
    window.target_input.setText("https://pentest-ground.com:4280/vulnerabilities/xss_r/?name=test")

    assert window._target_output_name() == "pentest-ground.com"
    assert window._report_path() == tmp_path / "reports" / "pentest-ground.com" / "pentest-ground.com_report.md"

    window.close()
    app.processEvents()
