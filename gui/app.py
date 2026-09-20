"""Desktop GUI for OSINT Agent."""

from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path
from urllib.parse import urlparse

import yaml
from PySide6.QtCore import QProcess, Qt, QUrl
from PySide6.QtGui import QAction, QDesktopServices, QFont
from PySide6.QtWebEngineWidgets import QWebEngineView
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QDoubleSpinBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QPlainTextEdit,
    QScrollArea,
    QSizePolicy,
    QSpinBox,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from gui.graph import build_display_graph, render_gravis_html
from agents import get_llm_config
from core.keyvault import KEY_SPECS, KeyVault
from modules import MODULE_REGISTRY, get_all_module_ids
from tools.external import tools_available


ROOT_DIR = Path(__file__).resolve().parent.parent
ORCHESTRATOR = ROOT_DIR / "orchestrator.py"
TOOLS_REQUIREMENTS = ROOT_DIR / "tools_requirements.txt"

TOOL_PRIORITIES = {
    "nuclei": ("minimum", "Template-based vulnerability checks"),
    "httpx": ("minimum", "HTTP probing and technology signals"),
    "katana": ("minimum", "Modern crawling and JavaScript endpoint discovery"),
    "gau": ("minimum", "Archived URLs for parameter discovery"),
    "ffuf": ("minimum", "Content and path discovery"),
    "dalfox": ("minimum", "Secondary XSS engine and PoC extraction"),
    "sqlmap": ("minimum", "SQL injection confirmation"),
    "arjun": ("minimum", "Hidden parameter discovery"),
    "paramspider": ("minimum", "Archived parameterized URL discovery"),
    "whatweb": ("minimum", "Technology fingerprinting"),
    "interactsh-client": ("minimum", "OOB callback confirmation"),
    "hakrawler": ("crawl", "Fallback web crawler"),
    "gobuster": ("crawl", "Content discovery"),
    "feroxbuster": ("crawl", "Content discovery"),
    "nmap": ("network", "Network service discovery"),
    "naabu": ("network", "Fast port scanning"),
    "masscan": ("network", "Large-scale port scanning"),
    "dnsx": ("network", "Bulk DNS resolution"),
    "subfinder": ("network", "Passive subdomain discovery"),
    "amass": ("network", "Passive subdomain discovery"),
    "nikto": ("web", "Web server checks"),
    "wpscan": ("web", "WordPress checks"),
    "corsy": ("web", "CORS checks"),
    "smuggler": ("web", "HTTP request smuggling checks"),
    "openredirex": ("web", "Open redirect checks"),
    "commix": ("web", "Command injection checks"),
    "testssl.sh": ("tls", "TLS configuration checks"),
    "gitleaks": ("osint", "Secret scanning"),
    "trufflehog": ("osint", "Secret scanning"),
    "theHarvester": ("osint", "Email and subdomain OSINT"),
    "maigret": ("osint", "Username OSINT"),
    "holehe": ("osint", "Email registration checks"),
    "searchsploit": ("exploit", "Exploit-DB lookup"),
    "gowitness": ("visual", "Screenshots"),
}


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("OSINT Agent")
        self.resize(1280, 820)
        self.process: QProcess | None = None
        self.running_report = False
        self.report_after_process = False
        self.current_assets = {"nodes": [], "edges": []}
        self.current_module = {}
        self.current_evidence = {"items": []}
        self.output_dir = ROOT_DIR / "reports"
        self.config_path = ROOT_DIR / "config.yaml"
        self._build_ui()
        self._apply_style()
        self._load_settings_form()
        self._refresh_module_list()
        self._refresh_key_status()
        self._refresh_tools_status()
        self._prefer_llm_if_ready()
        self._update_operation_context()

    def _build_ui(self):
        root = QWidget()
        layout = QVBoxLayout(root)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(10)

        header = QHBoxLayout()
        title_stack = QVBoxLayout()
        title = QLabel("RED TEAM OPS CONSOLE")
        title.setObjectName("title")
        subtitle = QLabel("OSINT collection, exposure mapping, evidence handling")
        subtitle.setObjectName("subtitle")
        title_stack.addWidget(title)
        title_stack.addWidget(subtitle)
        self.status_label = QLabel("Idle")
        self.status_label.setObjectName("status")
        header.addLayout(title_stack)
        header.addStretch(1)
        header.addWidget(self.status_label)
        layout.addLayout(header)

        workspace = QTabWidget()
        workspace.setObjectName("workspaceTabs")
        workspace.setDocumentMode(True)
        workspace.tabBar().setUsesScrollButtons(True)

        operations = QWidget()
        operations_layout = QVBoxLayout(operations)
        operations_layout.setContentsMargins(0, 0, 0, 0)
        splitter = QSplitter(Qt.Horizontal)
        results = self._build_results()
        splitter.addWidget(self._build_controls())
        splitter.addWidget(results)
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)
        splitter.setCollapsible(0, False)
        splitter.setCollapsible(1, False)
        splitter.setSizes([380, 1020])
        operations_layout.addWidget(splitter, 1)

        workspace.addTab(operations, "Operations")
        workspace.addTab(self._build_settings_panel(), "Settings")
        layout.addWidget(workspace, 1)

        self.setCentralWidget(root)
        self._build_menu()

    def _build_menu(self):
        file_menu = self.menuBar().addMenu("File")
        open_output = QAction("Choose Output Directory", self)
        open_output.triggered.connect(self.choose_output_dir)
        file_menu.addAction(open_output)

        open_target = QAction("Open Target Folder", self)
        open_target.triggered.connect(self.open_target_folder)
        file_menu.addAction(open_target)

        reload_report = QAction("Reload Current Results", self)
        reload_report.triggered.connect(self.load_results)
        file_menu.addAction(reload_report)

        settings_menu = self.menuBar().addMenu("Settings")
        reload_settings = QAction("Reload Config", self)
        reload_settings.triggered.connect(self._load_settings_form)
        settings_menu.addAction(reload_settings)

        save_settings = QAction("Save Config", self)
        save_settings.triggered.connect(self._save_settings_form)
        settings_menu.addAction(save_settings)

    def _build_controls(self) -> QWidget:
        panel = QFrame()
        panel.setObjectName("sidePanel")
        panel.setMinimumWidth(0)
        layout = QVBoxLayout(panel)
        layout.setSpacing(12)

        target_box = QGroupBox("Mission Setup")
        form = QFormLayout(target_box)
        form.setRowWrapPolicy(QFormLayout.WrapLongRows)
        form.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)
        self.target_input = QLineEdit("get-ads.agency")
        self.target_input.setPlaceholderText("example.com")
        self.target_input.setMinimumWidth(0)
        self.target_input.textChanged.connect(self._update_operation_context)
        self.output_input = QLineEdit(str(self.output_dir))
        self.output_input.setReadOnly(True)
        self.output_input.setMinimumWidth(0)
        self.output_input.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        choose_output = QPushButton("Browse")
        choose_output.clicked.connect(self.choose_output_dir)
        output_row = QHBoxLayout()
        output_row.setContentsMargins(0, 0, 0, 0)
        output_row.addWidget(self.output_input, 1)
        output_row.addWidget(choose_output)
        form.addRow("Target", self.target_input)
        form.addRow("Output", output_row)

        self.mode_combo = QComboBox()
        self.mode_combo.addItems(["Auto", "LLM", "Single module"])
        self.mode_combo.setMinimumWidth(0)
        self.mode_combo.currentIndexChanged.connect(self._sync_mode)
        self.mode_combo.currentIndexChanged.connect(self._update_operation_context)
        self.stage_filter_combo = QComboBox()
        self.stage_filter_combo.setMinimumWidth(0)
        self.stage_filter_combo.addItem("All stages", 0)
        for stage in range(1, 7):
            self.stage_filter_combo.addItem(f"Stage {stage}", stage)
        self.stage_filter_combo.currentIndexChanged.connect(self._refresh_module_list)
        self.module_combo = QComboBox()
        self.module_combo.setMinimumWidth(0)
        self.module_combo.currentIndexChanged.connect(self._update_module_hint)
        self.module_combo.currentIndexChanged.connect(self._update_operation_context)
        self.module_hint = QLabel("-")
        self.module_hint.setWordWrap(True)
        self.active_check = QCheckBox("Active authorized")
        self.skip_auth_check = QCheckBox("Skip prompt")
        self.skip_auth_check.setChecked(True)
        self.auto_report_check = QCheckBox("Generate report after run")
        self.auto_report_check.setChecked(True)
        form.addRow("Mode", self.mode_combo)
        form.addRow("Stage", self.stage_filter_combo)
        form.addRow("Module", self.module_combo)
        form.addRow("Info", self.module_hint)
        form.addRow("", self.active_check)
        form.addRow("", self.skip_auth_check)
        form.addRow("", self.auto_report_check)
        layout.addWidget(target_box)

        ai_box = QGroupBox("AI Assist")
        ai_layout = QVBoxLayout(ai_box)
        self.llm_status_label = QLabel("LLM status: checking")
        self.llm_status_label.setWordWrap(True)
        self.llm_status_label.setObjectName("assistantStatus")
        self.llm_status_label.setMinimumWidth(0)
        self.ai_run_button = QPushButton("AI Guided Run")
        self.ai_run_button.clicked.connect(self.start_llm_scan)
        self.ai_plan_button = QPushButton("AI Attack Plan")
        self.ai_plan_button.clicked.connect(self.generate_attack_plan)
        ai_layout.addWidget(self.llm_status_label)
        ai_layout.addWidget(self.ai_run_button)
        ai_layout.addWidget(self.ai_plan_button)
        layout.addWidget(ai_box)

        action_box = QGroupBox("Execution Controls")
        action_layout = QGridLayout(action_box)
        self.run_button = QPushButton("Run")
        self.run_button.clicked.connect(self.start_scan)
        self.stop_button = QPushButton("Stop")
        self.stop_button.clicked.connect(self.stop_scan)
        self.stop_button.setEnabled(False)
        self.reload_button = QPushButton("Reload")
        self.reload_button.clicked.connect(self.load_results)
        self.clear_button = QPushButton("Clear Log")
        self.clear_button.clicked.connect(self.log_output.clear)
        self.generate_report_button = QPushButton("Report")
        self.generate_report_button.clicked.connect(self.generate_report)
        self.prioritize_button = QPushButton("Prioritize")
        self.prioritize_button.clicked.connect(self.prioritize_findings)
        self.submission_button = QPushButton("Submissions")
        self.submission_button.clicked.connect(self.generate_submissions)
        self.open_report_button = QPushButton("Open")
        self.open_report_button.clicked.connect(self.open_report)
        self.open_folder_button = QPushButton("Folder")
        self.open_folder_button.clicked.connect(self.open_target_folder)
        action_layout.addWidget(self.run_button, 0, 0)
        action_layout.addWidget(self.stop_button, 0, 1)
        action_layout.addWidget(self.reload_button, 1, 0)
        action_layout.addWidget(self.clear_button, 1, 1)
        action_layout.addWidget(self.generate_report_button, 2, 0)
        action_layout.addWidget(self.prioritize_button, 2, 1)
        action_layout.addWidget(self.submission_button, 3, 0)
        action_layout.addWidget(self.open_report_button, 3, 1)
        action_layout.addWidget(self.open_folder_button, 4, 0, 1, 2)
        layout.addWidget(action_box)

        summary_box = QGroupBox("Operational Telemetry")
        summary_layout = QVBoxLayout(summary_box)
        self.assets_value = QLabel("-")
        self.relations_value = QLabel("-")
        self.findings_value = QLabel("-")
        self.evidence_value = QLabel("-")
        self.max_risk_value = QLabel("-")
        self.critical_high_value = QLabel("-")
        self.requests_value = QLabel("-")
        self.completed_value = QLabel("-")
        self.skipped_value = QLabel("-")
        self.active_value = QLabel("-")
        self.report_value = QLabel("-")
        self.report_value.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.report_value.setWordWrap(True)
        self.report_value.setMinimumWidth(0)
        metrics_grid = QGridLayout()
        metric_cards = [
            ("Assets", self.assets_value, "info"),
            ("Relations", self.relations_value, "info"),
            ("Findings", self.findings_value, "warning"),
            ("Evidence", self.evidence_value, "success"),
            ("Max Risk", self.max_risk_value, "danger"),
            ("Crit/High", self.critical_high_value, "danger"),
            ("Requests", self.requests_value, "info"),
            ("Complete", self.completed_value, "success"),
        ]
        for index, (label, value_label, tone) in enumerate(metric_cards):
            metrics_grid.addWidget(self._metric_card(label, value_label, tone), index // 2, index % 2)
        summary_layout.addLayout(metrics_grid)
        secondary_layout = QFormLayout()
        secondary_layout.addRow("Skipped", self.skipped_value)
        secondary_layout.addRow("Auth modules", self.active_value)
        secondary_layout.addRow("Report", self.report_value)
        summary_layout.addLayout(secondary_layout)
        layout.addWidget(summary_box)

        key_box = QGroupBox("Access Readiness")
        key_layout = QVBoxLayout(key_box)
        self.keys_table = QTableWidget(0, 3)
        self.keys_table.setHorizontalHeaderLabels(["Service", "Ready", "Key"])
        self.keys_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.keys_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.keys_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.keys_table.setMinimumWidth(0)
        self.keys_table.setMaximumHeight(180)
        key_layout.addWidget(self.keys_table)
        self.refresh_keys_button = QPushButton("Refresh Keys")
        self.refresh_keys_button.clicked.connect(self._refresh_key_status)
        key_layout.addWidget(self.refresh_keys_button)
        layout.addWidget(key_box)

        layout.addStretch(1)
        scroll = QScrollArea()
        scroll.setObjectName("sideScroll")
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.setWidget(panel)
        scroll.setMinimumWidth(300)
        scroll.setMaximumWidth(460)
        scroll.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Expanding)
        return scroll

    def _build_settings_panel(self) -> QWidget:
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)

        settings_tabs = QTabWidget()
        settings_tabs.setDocumentMode(True)
        settings_tabs.tabBar().setUsesScrollButtons(True)
        settings_tabs.addTab(self._build_llm_settings_tab(), "LLM")
        settings_tabs.addTab(self._build_runtime_settings_tab(), "Runtime")
        settings_tabs.addTab(self._build_scanner_settings_tab(), "Scanner")
        settings_tabs.addTab(self._build_tools_settings_tab(), "Tools")
        settings_tabs.addTab(self._build_keys_settings_tab(), "API Keys")
        settings_tabs.addTab(self._build_raw_config_tab(), "Raw YAML")
        layout.addWidget(settings_tabs, 1)
        return panel

    def _build_llm_settings_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(12)

        llm_box = QGroupBox("LLM Provider")
        form = QFormLayout(llm_box)
        form.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)
        self.llm_model_combo = QComboBox()
        self.llm_model_combo.setEditable(True)
        self.llm_model_combo.addItems([
            "",
            "deepseek/deepseek-chat",
            "deepseek/deepseek-reasoner",
            "openai/gpt-4o",
            "openai/gpt-4.1",
            "openai/o4-mini",
            "anthropic/claude-sonnet-4-20250514",
            "groq/llama-3.3-70b-versatile",
            "openrouter/openai/gpt-4o",
            "ollama/llama3.1",
            "ollama/nemotron-3-super:cloud",
            "lm_studio/local-model",
        ])
        self.llm_model_combo.lineEdit().setPlaceholderText("provider/model or shortcut")
        self.llm_api_key_input = QLineEdit()
        self.llm_api_key_input.setEchoMode(QLineEdit.Password)
        self.llm_api_key_input.setPlaceholderText("Stored in config.yaml; env vars still work")
        self.llm_temperature_spin = QDoubleSpinBox()
        self.llm_temperature_spin.setRange(0.0, 2.0)
        self.llm_temperature_spin.setSingleStep(0.1)
        self.llm_temperature_spin.setDecimals(2)
        self.llm_max_tokens_spin = QSpinBox()
        self.llm_max_tokens_spin.setRange(256, 128000)
        self.llm_max_tokens_spin.setSingleStep(256)
        form.addRow("Model", self.llm_model_combo)
        form.addRow("API key", self.llm_api_key_input)
        form.addRow("Temperature", self.llm_temperature_spin)
        form.addRow("Max tokens", self.llm_max_tokens_spin)
        layout.addWidget(llm_box)

        status_box = QGroupBox("LLM Status")
        status_layout = QVBoxLayout(status_box)
        self.llm_settings_status = QLabel("Not checked")
        self.llm_settings_status.setObjectName("assistantStatus")
        self.llm_settings_status.setWordWrap(True)
        status_layout.addWidget(self.llm_settings_status)
        button_row = QHBoxLayout()
        self.save_llm_button = QPushButton("Save LLM Settings")
        self.save_llm_button.clicked.connect(self._save_settings_form)
        self.reload_llm_button = QPushButton("Reload")
        self.reload_llm_button.clicked.connect(self._load_settings_form)
        self.refresh_llm_status_button = QPushButton("Refresh Status")
        self.refresh_llm_status_button.clicked.connect(self._update_operation_context)
        button_row.addWidget(self.save_llm_button)
        button_row.addWidget(self.reload_llm_button)
        button_row.addWidget(self.refresh_llm_status_button)
        status_layout.addLayout(button_row)
        layout.addWidget(status_box)
        layout.addStretch(1)
        return tab

    def _build_runtime_settings_tab(self) -> QWidget:
        tab = QWidget()
        outer = QVBoxLayout(tab)
        outer.setContentsMargins(0, 0, 0, 0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        body = QWidget()
        layout = QVBoxLayout(body)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(12)

        target_box = QGroupBox("Target Defaults")
        target_form = QFormLayout(target_box)
        target_form.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)
        self.config_target_domain_input = QLineEdit()
        self.config_target_domain_input.setPlaceholderText("Default target when CLI does not override")
        self.config_scope_input = QPlainTextEdit()
        self.config_scope_input.setPlaceholderText("One allowed domain or pattern per line")
        self.config_scope_input.setMaximumHeight(110)
        self.config_authorization_combo = QComboBox()
        self.config_authorization_combo.addItems(["pending", "confirmed", "denied"])
        self.config_mode_combo = QComboBox()
        self.config_mode_combo.addItems(["passive", "active", "deep"])
        target_form.addRow("Domain", self.config_target_domain_input)
        target_form.addRow("Scope", self.config_scope_input)
        target_form.addRow("Authorization", self.config_authorization_combo)
        target_form.addRow("Mode", self.config_mode_combo)
        layout.addWidget(target_box)

        detectability_box = QGroupBox("Detectability")
        detectability_form = QFormLayout(detectability_box)
        self.config_default_detectability_combo = QComboBox()
        self.config_default_detectability_combo.addItems(["low", "medium", "high"])
        self.config_allow_high_check = QCheckBox("Allow high-detectability modules")
        detectability_form.addRow("Default", self.config_default_detectability_combo)
        detectability_form.addRow("", self.config_allow_high_check)
        layout.addWidget(detectability_box)

        module_box = QGroupBox("Module Behavior")
        module_form = QFormLayout(module_box)
        self.config_auto_run_check = QCheckBox("Auto-run module chain")
        self.config_skip_on_waf_check = QCheckBox("Skip modules when WAF blocks")
        self.config_record_http_evidence_check = QCheckBox("Record HTTP evidence")
        self.config_max_empty_spin = QSpinBox()
        self.config_max_empty_spin.setRange(0, 100)
        module_form.addRow("", self.config_auto_run_check)
        module_form.addRow("", self.config_skip_on_waf_check)
        module_form.addRow("", self.config_record_http_evidence_check)
        module_form.addRow("Max empty modules", self.config_max_empty_spin)
        layout.addWidget(module_box)

        rate_box = QGroupBox("Rate Limits")
        rate_layout = QGridLayout(rate_box)
        rate_layout.addWidget(QLabel("Scope"), 0, 0)
        rate_layout.addWidget(QLabel("Concurrent"), 0, 1)
        rate_layout.addWidget(QLabel("Per minute"), 0, 2)
        self.rate_limit_inputs = {}
        for row, name in enumerate(["default", "dns", "http", "scan"], start=1):
            concurrent = QSpinBox()
            concurrent.setRange(1, 500)
            per_minute = QSpinBox()
            per_minute.setRange(1, 10000)
            self.rate_limit_inputs[name] = {"concurrent": concurrent, "per_minute": per_minute}
            rate_layout.addWidget(QLabel(name), row, 0)
            rate_layout.addWidget(concurrent, row, 1)
            rate_layout.addWidget(per_minute, row, 2)
        layout.addWidget(rate_box)

        button_row = QHBoxLayout()
        save_button = QPushButton("Save Runtime Settings")
        save_button.clicked.connect(self._save_settings_form)
        reload_button = QPushButton("Reload")
        reload_button.clicked.connect(self._load_settings_form)
        button_row.addStretch(1)
        button_row.addWidget(reload_button)
        button_row.addWidget(save_button)
        layout.addLayout(button_row)
        layout.addStretch(1)

        scroll.setWidget(body)
        outer.addWidget(scroll, 1)
        return tab

    def _build_scanner_settings_tab(self) -> QWidget:
        tab = QWidget()
        outer = QVBoxLayout(tab)
        outer.setContentsMargins(0, 0, 0, 0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        body = QWidget()
        layout = QVBoxLayout(body)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(12)

        auth_box = QGroupBox("Authenticated Testing")
        auth_form = QFormLayout(auth_box)
        auth_form.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)
        self.auth_bearer_input = QLineEdit()
        self.auth_bearer_input.setEchoMode(QLineEdit.Password)
        self.auth_bearer_input.setPlaceholderText("Bearer token applied to HTTP/browser probes")
        self.auth_cookie_input = QLineEdit()
        self.auth_cookie_input.setEchoMode(QLineEdit.Password)
        self.auth_cookie_input.setPlaceholderText("session=...; other=...")
        self.auth_headers_input = QPlainTextEdit()
        self.auth_headers_input.setPlaceholderText("One header per line, for example:\nAuthorization: Bearer ...\nX-API-Key: ...")
        self.auth_headers_input.setMaximumHeight(110)
        self.auth_probe_backoff_spin = QSpinBox()
        self.auth_probe_backoff_spin.setRange(0, 3600)
        auth_form.addRow("Bearer token", self.auth_bearer_input)
        auth_form.addRow("Cookie header", self.auth_cookie_input)
        auth_form.addRow("Headers", self.auth_headers_input)
        auth_form.addRow("Auth probe backoff", self.auth_probe_backoff_spin)
        layout.addWidget(auth_box)

        xss_box = QGroupBox("XSS Detection")
        xss_form = QFormLayout(xss_box)
        self.xss_browser_confirm_check = QCheckBox("Confirm execution with Playwright/Chromium")
        self.xss_max_points_spin = QSpinBox()
        self.xss_max_points_spin.setRange(1, 5000)
        self.xss_dalfox_timeout_spin = QSpinBox()
        self.xss_dalfox_timeout_spin.setRange(30, 7200)
        xss_form.addRow("", self.xss_browser_confirm_check)
        xss_form.addRow("Max injection points", self.xss_max_points_spin)
        xss_form.addRow("Dalfox timeout", self.xss_dalfox_timeout_spin)
        layout.addWidget(xss_box)

        nuclei_box = QGroupBox("Nuclei")
        nuclei_form = QFormLayout(nuclei_box)
        self.nuclei_full_cve_check = QCheckBox("Run full CVE pass only on confirmed apex")
        nuclei_form.addRow("", self.nuclei_full_cve_check)
        layout.addWidget(nuclei_box)

        fast_scan_box = QGroupBox("Fast Exposure Scan")
        fast_scan_form = QFormLayout(fast_scan_box)
        fast_scan_form.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)
        self.fast_scan_paths_input = QPlainTextEdit()
        self.fast_scan_paths_input.setPlaceholderText("High-signal paths, one per line")
        self.fast_scan_paths_input.setMaximumHeight(120)
        self.fast_scan_timeout_spin = QSpinBox()
        self.fast_scan_timeout_spin.setRange(1, 30)
        self.fast_scan_concurrency_spin = QSpinBox()
        self.fast_scan_concurrency_spin.setRange(1, 50)
        self.fast_scan_max_paths_spin = QSpinBox()
        self.fast_scan_max_paths_spin.setRange(1, 500)
        fast_scan_form.addRow("Paths", self.fast_scan_paths_input)
        fast_scan_form.addRow("Timeout", self.fast_scan_timeout_spin)
        fast_scan_form.addRow("Concurrency", self.fast_scan_concurrency_spin)
        fast_scan_form.addRow("Max paths", self.fast_scan_max_paths_spin)
        layout.addWidget(fast_scan_box)

        oob_box = QGroupBox("OOB Callback Infrastructure")
        oob_form = QFormLayout(oob_box)
        oob_form.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)
        self.oob_callback_domain_input = QLineEdit()
        self.oob_callback_domain_input.setPlaceholderText("oob.example.com")
        self.oob_server_url_input = QLineEdit()
        self.oob_server_url_input.setPlaceholderText("https://interactsh-wrapper.example")
        self.oob_poll_url_input = QLineEdit()
        self.oob_poll_url_input.setPlaceholderText("https://interactsh-wrapper.example/interactions")
        self.oob_token_input = QLineEdit()
        self.oob_token_input.setEchoMode(QLineEdit.Password)
        self.oob_poll_interval_spin = QSpinBox()
        self.oob_poll_interval_spin.setRange(1, 300)
        self.oob_poll_timeout_spin = QSpinBox()
        self.oob_poll_timeout_spin.setRange(1, 3600)
        oob_form.addRow("Callback domain", self.oob_callback_domain_input)
        oob_form.addRow("Server URL", self.oob_server_url_input)
        oob_form.addRow("Poll URL", self.oob_poll_url_input)
        oob_form.addRow("Token", self.oob_token_input)
        oob_form.addRow("Poll interval", self.oob_poll_interval_spin)
        oob_form.addRow("Poll timeout", self.oob_poll_timeout_spin)
        layout.addWidget(oob_box)

        button_row = QHBoxLayout()
        save_button = QPushButton("Save Scanner Settings")
        save_button.clicked.connect(self._save_settings_form)
        reload_button = QPushButton("Reload")
        reload_button.clicked.connect(self._load_settings_form)
        button_row.addStretch(1)
        button_row.addWidget(reload_button)
        button_row.addWidget(save_button)
        layout.addLayout(button_row)
        layout.addStretch(1)

        scroll.setWidget(body)
        outer.addWidget(scroll, 1)
        return tab

    def _build_tools_settings_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(12)

        tools_box = QGroupBox("External Tool Readiness")
        tools_layout = QVBoxLayout(tools_box)
        self.tools_table = QTableWidget(0, 4)
        self.tools_table.setHorizontalHeaderLabels(["Tool", "Ready", "Priority", "Purpose"])
        self.tools_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.tools_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.tools_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.tools_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        tools_layout.addWidget(self.tools_table)
        tool_buttons = QHBoxLayout()
        self.refresh_tools_button = QPushButton("Refresh Tools")
        self.refresh_tools_button.clicked.connect(self._refresh_tools_status)
        self.open_tools_requirements_button = QPushButton("Open Requirements")
        self.open_tools_requirements_button.clicked.connect(self.open_tools_requirements)
        tool_buttons.addStretch(1)
        tool_buttons.addWidget(self.refresh_tools_button)
        tool_buttons.addWidget(self.open_tools_requirements_button)
        tools_layout.addLayout(tool_buttons)
        layout.addWidget(tools_box, 2)

        requirements_box = QGroupBox("tools_requirements.txt")
        requirements_layout = QVBoxLayout(requirements_box)
        self.tools_requirements_preview = QPlainTextEdit()
        self.tools_requirements_preview.setReadOnly(True)
        self.tools_requirements_preview.setLineWrapMode(QPlainTextEdit.NoWrap)
        self.tools_requirements_preview.setFont(QFont("Menlo", 11))
        requirements_layout.addWidget(self.tools_requirements_preview)
        layout.addWidget(requirements_box, 1)
        return tab

    def _build_keys_settings_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(12)

        key_box = QGroupBox("Service API Keys")
        key_layout = QGridLayout(key_box)
        key_layout.addWidget(QLabel("Service"), 0, 0)
        key_layout.addWidget(QLabel("Config value"), 0, 1)
        key_layout.addWidget(QLabel("Environment fallback"), 0, 2)
        self.api_key_inputs = {}
        for row, (service, spec) in enumerate(sorted(KEY_SPECS.items()), start=1):
            key_input = QLineEdit()
            key_input.setEchoMode(QLineEdit.Password)
            key_input.setPlaceholderText("leave blank to use env")
            self.api_key_inputs[service] = key_input
            env_label = QLabel(", ".join(spec.env))
            env_label.setWordWrap(True)
            key_layout.addWidget(QLabel(spec.label), row, 0)
            key_layout.addWidget(key_input, row, 1)
            key_layout.addWidget(env_label, row, 2)
        key_layout.setColumnStretch(1, 2)
        key_layout.setColumnStretch(2, 2)
        layout.addWidget(key_box)

        button_row = QHBoxLayout()
        save_button = QPushButton("Save API Keys")
        save_button.clicked.connect(self._save_settings_form)
        reload_button = QPushButton("Reload")
        reload_button.clicked.connect(self._load_settings_form)
        button_row.addStretch(1)
        button_row.addWidget(reload_button)
        button_row.addWidget(save_button)
        layout.addLayout(button_row)
        layout.addStretch(1)
        return tab

    def _build_raw_config_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(12, 12, 12, 12)
        self.raw_config_editor = QPlainTextEdit()
        self.raw_config_editor.setLineWrapMode(QPlainTextEdit.NoWrap)
        self.raw_config_editor.setFont(QFont("Menlo", 12))
        layout.addWidget(self.raw_config_editor, 1)
        button_row = QHBoxLayout()
        validate_button = QPushButton("Apply Raw YAML")
        validate_button.clicked.connect(self._save_raw_config_editor)
        reload_button = QPushButton("Reload Raw")
        reload_button.clicked.connect(self._load_raw_config_editor)
        button_row.addStretch(1)
        button_row.addWidget(reload_button)
        button_row.addWidget(validate_button)
        layout.addLayout(button_row)
        return tab

    def _build_results(self) -> QWidget:
        results_widget = QWidget()
        results_widget.setMinimumWidth(0)
        results_layout = QVBoxLayout(results_widget)
        results_layout.setContentsMargins(0, 0, 0, 0)
        results_layout.setSpacing(10)

        ops_strip = QFrame()
        ops_strip.setObjectName("opsStrip")
        ops_layout = QGridLayout(ops_strip)
        ops_layout.setContentsMargins(14, 10, 14, 10)
        self.operation_target_label = QLabel("Target: -")
        self.operation_target_label.setObjectName("opsPrimary")
        self.operation_target_label.setWordWrap(True)
        self.operation_target_label.setMinimumWidth(0)
        self.operation_mode_label = QLabel("Mode: -")
        self.operation_mode_label.setObjectName("opsSecondary")
        self.operation_mode_label.setWordWrap(True)
        self.operation_mode_label.setMinimumWidth(0)
        self.operation_state_label = QLabel("Ready")
        self.operation_state_label.setObjectName("opsState")
        self.operation_state_label.setMinimumWidth(0)
        self.progress_bar = QProgressBar()
        self.progress_bar.setMinimumWidth(0)
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(True)
        self.exposure_label = QLabel("Exposure map: waiting for data")
        self.exposure_label.setObjectName("opsSecondary")
        self.exposure_label.setWordWrap(True)
        self.exposure_label.setMinimumWidth(0)
        ops_layout.addWidget(self.operation_target_label, 0, 0)
        ops_layout.addWidget(self.operation_mode_label, 1, 0)
        ops_layout.addWidget(self.operation_state_label, 0, 1, 2, 1)
        ops_layout.addWidget(self.progress_bar, 0, 2)
        ops_layout.addWidget(self.exposure_label, 1, 2)
        ops_layout.setColumnStretch(0, 2)
        ops_layout.setColumnStretch(2, 3)
        results_layout.addWidget(ops_strip)

        self.results_tabs = QTabWidget()
        self.results_tabs.setDocumentMode(True)
        self.results_tabs.tabBar().setUsesScrollButtons(True)
        self.results_tabs.tabBar().setElideMode(Qt.ElideRight)

        self.log_output = QPlainTextEdit()
        self.log_output.setReadOnly(True)
        self.log_output.setLineWrapMode(QPlainTextEdit.NoWrap)
        self.log_output.setFont(QFont("Menlo", 12))
        self.results_tabs.addTab(self.log_output, "Log")

        self.findings_table = QTableWidget(0, 8)
        self.findings_table.setHorizontalHeaderLabels([
            "ID", "Priority", "Severity", "Score", "Confidence", "Title", "Category", "Assets",
        ])
        header = self.findings_table.horizontalHeader()
        header.setSectionResizeMode(5, QHeaderView.Stretch)
        header.setSectionResizeMode(6, QHeaderView.Stretch)
        self.findings_table.setSortingEnabled(True)
        self.results_tabs.addTab(self.findings_table, "Findings")

        self.assets_table = QTableWidget(0, 4)
        self.assets_table.setHorizontalHeaderLabels(["Type", "Value", "Confidence", "Sources"])
        self.assets_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.results_tabs.addTab(self.assets_table, "Assets")

        self.modules_table = QTableWidget(0, 8)
        self.modules_table.setHorizontalHeaderLabels([
            "Stage", "Module", "Status", "Detectability", "Requests", "Assets +", "Findings +", "Error",
        ])
        self.modules_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.modules_table.horizontalHeader().setSectionResizeMode(7, QHeaderView.Stretch)
        self.modules_table.setSortingEnabled(True)
        self.results_tabs.addTab(self.modules_table, "Modules")

        self.evidence_table = QTableWidget(0, 5)
        self.evidence_table.setHorizontalHeaderLabels(["ID", "Module", "Type", "Subject", "Path"])
        self.evidence_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.evidence_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        self.evidence_table.cellDoubleClicked.connect(self._open_evidence_cell)
        self.results_tabs.addTab(self.evidence_table, "Evidence")

        graph_widget = QWidget()
        graph_layout = QVBoxLayout(graph_widget)
        graph_layout.setContentsMargins(0, 0, 0, 0)
        graph_header = QGridLayout()
        self.graph_summary = QLabel("No graph loaded")
        self.graph_summary.setWordWrap(True)
        self.graph_summary.setMinimumWidth(0)
        self.graph_aggregate_check = QCheckBox("Group dense types")
        self.graph_aggregate_check.setChecked(True)
        self.graph_aggregate_check.stateChanged.connect(self.refresh_graph)
        self.graph_labels_check = QCheckBox("Labels")
        self.graph_labels_check.setChecked(False)
        self.graph_labels_check.stateChanged.connect(self.refresh_graph)
        self.graph_edges_check = QCheckBox("Relations")
        self.graph_edges_check.setChecked(True)
        self.graph_edges_check.stateChanged.connect(self.refresh_graph)
        self.fit_graph_button = QPushButton("Fit")
        self.fit_graph_button.clicked.connect(self.refresh_graph)
        graph_header.addWidget(self.graph_summary, 0, 0, 1, 4)
        graph_header.addWidget(self.graph_aggregate_check, 1, 0)
        graph_header.addWidget(self.graph_labels_check, 1, 1)
        graph_header.addWidget(self.graph_edges_check, 1, 2)
        graph_header.addWidget(self.fit_graph_button, 1, 3)
        graph_header.setColumnStretch(0, 1)
        graph_layout.addLayout(graph_header)
        self.graph_view = QWebEngineView()
        self.graph_view.setMinimumSize(0, 0)
        graph_layout.addWidget(self.graph_view, 1)
        self.results_tabs.addTab(graph_widget, "Graph")

        self.submissions_table = QTableWidget(0, 3)
        self.submissions_table.setHorizontalHeaderLabels(["File", "Size", "Path"])
        self.submissions_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.submissions_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.submissions_table.cellDoubleClicked.connect(self._open_submission_cell)
        self.results_tabs.addTab(self.submissions_table, "Submissions")

        report_widget = QWidget()
        report_layout = QVBoxLayout(report_widget)
        report_layout.setContentsMargins(0, 0, 0, 0)
        self.report_path_label = QLabel("No report loaded")
        self.report_path_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.report_path_label.setWordWrap(True)
        self.report_path_label.setMinimumWidth(0)
        report_layout.addWidget(self.report_path_label)

        report_tabs = QTabWidget()
        report_tabs.tabBar().setUsesScrollButtons(True)
        report_tabs.tabBar().setElideMode(Qt.ElideRight)
        self.report_preview = QTextEdit()
        self.report_preview.setReadOnly(True)
        self.report_raw = QPlainTextEdit()
        self.report_raw.setReadOnly(True)
        self.report_raw.setLineWrapMode(QPlainTextEdit.NoWrap)
        self.report_raw.setFont(QFont("Menlo", 12))
        report_tabs.addTab(self.report_preview, "Rendered")
        report_tabs.addTab(self.report_raw, "Markdown")
        report_layout.addWidget(report_tabs, 1)
        self.results_tabs.addTab(report_widget, "Report")

        attack_plan_widget = QWidget()
        attack_plan_layout = QVBoxLayout(attack_plan_widget)
        attack_plan_layout.setContentsMargins(0, 0, 0, 0)
        self.attack_plan_path_label = QLabel("No attack plan loaded")
        self.attack_plan_path_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.attack_plan_path_label.setWordWrap(True)
        self.attack_plan_path_label.setMinimumWidth(0)
        attack_plan_layout.addWidget(self.attack_plan_path_label)
        self.attack_plan_preview = QTextEdit()
        self.attack_plan_preview.setReadOnly(True)
        attack_plan_layout.addWidget(self.attack_plan_preview, 1)
        self.results_tabs.addTab(attack_plan_widget, "Attack Plan")

        self.summary_json = QPlainTextEdit()
        self.summary_json.setReadOnly(True)
        self.summary_json.setLineWrapMode(QPlainTextEdit.NoWrap)
        self.summary_json.setFont(QFont("Menlo", 12))
        self.results_tabs.addTab(self.summary_json, "Summary JSON")

        results_layout.addWidget(self.results_tabs, 1)
        return results_widget

    def _metric_card(self, label: str, value_label: QLabel, tone: str) -> QFrame:
        card = QFrame()
        card.setObjectName("metricCard")
        card.setProperty("tone", tone)
        layout = QVBoxLayout(card)
        layout.setContentsMargins(10, 8, 10, 8)
        label_widget = QLabel(label.upper())
        label_widget.setObjectName("metricLabel")
        value_label.setObjectName("metricValue")
        layout.addWidget(label_widget)
        layout.addWidget(value_label)
        return card

    def _refresh_module_list(self):
        selected = self.module_combo.currentData() if hasattr(self, "module_combo") else None
        self.module_combo.clear()
        stage_filter = self.stage_filter_combo.currentData() if hasattr(self, "stage_filter_combo") else 0
        for module_id in get_all_module_ids():
            entry = MODULE_REGISTRY[module_id]
            if stage_filter and entry.get("stage") != stage_filter:
                continue
            auth = " [AUTH]" if entry.get("requires_auth") else ""
            label = f"S{entry['stage']}  {module_id}{auth}"
            self.module_combo.addItem(label, module_id)
            if selected == module_id:
                self.module_combo.setCurrentIndex(self.module_combo.count() - 1)
        self._sync_mode()
        self._update_module_hint()

    def _sync_mode(self):
        self.module_combo.setEnabled(self.mode_combo.currentText() == "Single module")
        self.stage_filter_combo.setEnabled(self.mode_combo.currentText() == "Single module")
        if hasattr(self, "ai_run_button"):
            self.ai_run_button.setEnabled(self.mode_combo.currentText() != "Single module")

    def _update_module_hint(self):
        module_id = self.module_combo.currentData()
        entry = MODULE_REGISTRY.get(module_id or "", {})
        if not entry:
            self.module_hint.setText("-")
            return
        auth = "auth required" if entry.get("requires_auth") else "passive"
        deps = ", ".join(entry.get("depends_on", [])) or "none"
        self.module_hint.setText(
            f"Stage {entry.get('stage')} · {entry.get('detectability')} · {auth} · deps: {deps}"
        )

    def _llm_status(self) -> tuple[bool, str]:
        llm = get_llm_config(self._read_config())
        model = llm.get("model", "")
        local_prefixes = ("ollama/", "lm_studio/", "hosted_vllm/")
        needs_key = bool(model) and not model.startswith(local_prefixes)
        ready = bool(model) and (bool(llm.get("api_key")) or not needs_key)
        if ready:
            return True, f"LLM ready: {model}"
        return False, f"LLM key missing for {model or 'configured model'}"

    def _prefer_llm_if_ready(self):
        ready, _message = self._llm_status()
        if ready and hasattr(self, "mode_combo"):
            index = self.mode_combo.findText("LLM")
            if index >= 0:
                self.mode_combo.setCurrentIndex(index)

    def start_llm_scan(self):
        index = self.mode_combo.findText("LLM")
        if index >= 0:
            self.mode_combo.setCurrentIndex(index)
        self.start_scan()

    def choose_output_dir(self):
        selected = QFileDialog.getExistingDirectory(
            self,
            "Output Directory",
            str(self.output_dir),
        )
        if selected:
            self.output_dir = Path(selected)
            self.output_input.setText(str(self.output_dir))
            self._update_operation_context()

    def start_scan(self):
        target = self.target_input.text().strip()
        if not target:
            QMessageBox.warning(self, "Target Required", "Enter a target domain.")
            return
        if self.process and self.process.state() != QProcess.NotRunning:
            return

        args = [str(ORCHESTRATOR), "-t", target, "-o", str(self.output_dir)]
        mode = self.mode_combo.currentText()
        if self.active_check.isChecked():
            args.append("--active")
            if self.skip_auth_check.isChecked():
                args.append("--skip-auth-check")
        elif mode == "LLM":
            args.extend(["--mode", "llm"])

        if mode == "Single module":
            args.extend(["--module", self.module_combo.currentData()])

        self.report_after_process = (
            self.auto_report_check.isChecked()
            and mode in ("Single module", "LLM")
            and self.module_combo.currentData() != "reporting"
        )
        self.running_report = False
        self._start_process(args)

    def generate_report(self):
        self.run_module_action("reporting", report_run=True)

    def prioritize_findings(self):
        self.run_module_action("risk_prioritization")

    def generate_submissions(self):
        self.run_module_action("bounty_submission")

    def generate_attack_plan(self):
        self.run_module_action("attack_planner")

    def run_module_action(self, module_id: str, report_run: bool = False):
        target = self.target_input.text().strip()
        if not target:
            QMessageBox.warning(self, "Target Required", "Enter a target domain.")
            return
        if self.process and self.process.state() != QProcess.NotRunning:
            return
        args = [
            str(ORCHESTRATOR),
            "-t", target,
            "-o", str(self.output_dir),
            "--module", module_id,
        ]
        self._start_process(args, report_run=report_run)

    def open_report(self):
        path = self._report_path()
        if not path.exists():
            QMessageBox.information(self, "Report Missing", "No report exists for this target yet.")
            return
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(path)))

    def open_target_folder(self):
        path = self.output_dir / self._target_output_name()
        if not path.exists():
            QMessageBox.information(self, "Folder Missing", "No output folder exists for this target yet.")
            return
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(path)))

    def _start_process(self, args: list[str], report_run: bool = False):
        self.running_report = report_run
        self.log_output.appendPlainText(f"$ {sys.executable} {' '.join(args)}\n")
        self.status_label.setText("Running")
        self.operation_state_label.setText("Operation active")
        if report_run:
            self.status_label.setText("Generating report")
            self.operation_state_label.setText("Report generation")
        self.run_button.setEnabled(False)
        self.ai_run_button.setEnabled(False)
        self.ai_plan_button.setEnabled(False)
        self.generate_report_button.setEnabled(False)
        self.prioritize_button.setEnabled(False)
        self.submission_button.setEnabled(False)
        self.stop_button.setEnabled(True)

        self.process = QProcess(self)
        self.process.setProgram(sys.executable)
        self.process.setArguments(args)
        env = os.environ.copy()
        env["PYTHONUNBUFFERED"] = "1"
        self.process.setProcessEnvironment(self._qt_environment(env))
        self.process.readyReadStandardOutput.connect(self._read_stdout)
        self.process.readyReadStandardError.connect(self._read_stderr)
        self.process.finished.connect(self._process_finished)
        self.process.start()

    def stop_scan(self):
        if self.process and self.process.state() != QProcess.NotRunning:
            self.process.terminate()
            if not self.process.waitForFinished(2000):
                self.process.kill()

    def _read_stdout(self):
        if not self.process:
            return
        text = bytes(self.process.readAllStandardOutput()).decode("utf-8", errors="replace")
        self.log_output.appendPlainText(text.rstrip())

    def _read_stderr(self):
        if not self.process:
            return
        text = bytes(self.process.readAllStandardError()).decode("utf-8", errors="replace")
        self.log_output.appendPlainText(text.rstrip())

    def _process_finished(self, exit_code: int, _status):
        was_report = self.running_report
        self.running_report = False
        self.load_results()
        if (
            not was_report
            and exit_code == 0
            and (self.report_after_process or not self._report_path().exists())
        ):
            self.report_after_process = False
            self.generate_report()
            return

        self.report_after_process = False
        self.status_label.setText(f"Finished ({exit_code})")
        self.operation_state_label.setText(f"Finished ({exit_code})")
        self.run_button.setEnabled(True)
        self.ai_run_button.setEnabled(True)
        self.ai_plan_button.setEnabled(True)
        self.generate_report_button.setEnabled(True)
        self.prioritize_button.setEnabled(True)
        self.submission_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self._sync_mode()

    def load_results(self):
        target = self.target_input.text().strip()
        if not target:
            return
        base = self.output_dir / self._target_output_name()
        state_dir = base / "state"
        module = self._read_json(state_dir / "module.json", {})
        assets = self._read_json(state_dir / "assets.json", {"nodes": []})
        findings = self._read_json(state_dir / "findings.json", {"findings": []})
        evidence = self._read_json(state_dir / "evidence.json", {"items": []})
        summary_bundle = self._read_json(self._summary_path(), {})

        self.assets_value.setText(str(len(assets.get("nodes", []))))
        self.relations_value.setText(str(len(assets.get("edges", []))))
        self.findings_value.setText(str(len(findings.get("findings", []))))
        self.evidence_value.setText(str(len(evidence.get("items", []))))
        stats = module.get("stats", {})
        self.requests_value.setText(str(stats.get("total_requests", "-")))
        self.completed_value.setText(str(len(module.get("completed", []))))
        self.skipped_value.setText(str(len(module.get("skipped", []))))
        active_count = sum(1 for mid, entry in MODULE_REGISTRY.items() if entry.get("requires_auth"))
        self.active_value.setText(str(active_count))
        risk = summary_bundle.get("risk", {})
        self.max_risk_value.setText(str(risk.get("max_score", "-")))
        self.critical_high_value.setText(str(risk.get("critical_high", "-")))

        report_path = self._report_path()
        report_display = self._display_path(report_path) if report_path.exists() else "-"
        self.report_value.setText(report_display)
        self.report_value.setToolTip(str(report_path) if report_path.exists() else "")
        self.report_path_label.setText(report_display if report_path.exists() else "No report generated yet")
        self.report_path_label.setToolTip(str(report_path) if report_path.exists() else "")
        attack_plan_path = self._attack_plan_path()
        attack_plan_display = self._display_path(attack_plan_path) if attack_plan_path.exists() else ""
        self.attack_plan_path_label.setText(
            attack_plan_display if attack_plan_path.exists() else "No AI attack plan generated yet"
        )
        self.attack_plan_path_label.setToolTip(str(attack_plan_path) if attack_plan_path.exists() else "")
        self._load_findings(findings.get("findings", []))
        self._load_assets(assets.get("nodes", []))
        self._load_modules(module)
        self._load_evidence(evidence.get("items", []))
        self._load_submissions()
        self._load_summary_json(summary_bundle)
        self.current_assets = assets
        self.current_module = module
        self.current_evidence = evidence
        self._update_operation_context()
        self.refresh_graph()
        if report_path.exists():
            report_text = report_path.read_text(errors="replace")
            self.report_preview.setMarkdown(report_text)
            self.report_raw.setPlainText(report_text)
        else:
            message = "No report generated yet. Use the Report action or enable automatic report generation."
            self.report_preview.setPlainText(message)
            self.report_raw.setPlainText("")
        if attack_plan_path.exists():
            self.attack_plan_preview.setMarkdown(attack_plan_path.read_text(errors="replace"))
        else:
            self.attack_plan_preview.setPlainText(
                "No AI attack plan generated yet. Run AI Attack Plan after OSINT collection."
            )

    def _update_operation_context(self):
        if not hasattr(self, "operation_target_label"):
            return

        target = self.target_input.text().strip() if hasattr(self, "target_input") else ""
        mode = self.mode_combo.currentText() if hasattr(self, "mode_combo") else "-"
        module = self.module_combo.currentData() if hasattr(self, "module_combo") else "-"
        if mode != "Single module":
            module = "orchestrated chain"

        self.operation_target_label.setText(f"Target: {target or '-'}")
        self.operation_mode_label.setText(f"Mode: {mode} | Module: {module}")
        ready, llm_message = self._llm_status()
        self.llm_status_label.setText(llm_message)
        self.llm_status_label.setProperty("ready", ready)
        self.llm_status_label.style().unpolish(self.llm_status_label)
        self.llm_status_label.style().polish(self.llm_status_label)
        if hasattr(self, "llm_settings_status"):
            self.llm_settings_status.setText(llm_message)
            self.llm_settings_status.setProperty("ready", ready)
            self.llm_settings_status.style().unpolish(self.llm_settings_status)
            self.llm_settings_status.style().polish(self.llm_settings_status)

        module_state = self.current_module if isinstance(self.current_module, dict) else {}
        completed = len(module_state.get("completed", []))
        skipped = len(module_state.get("skipped", []))
        total = max(len(get_all_module_ids()), 1)
        progress = min(100, int((completed / total) * 100))
        self.progress_bar.setValue(progress)
        self.progress_bar.setFormat(f"{completed}/{total} modules complete")

        if self.process and self.process.state() != QProcess.NotRunning:
            return
        if completed or skipped:
            self.operation_state_label.setText("Results loaded")
        else:
            self.operation_state_label.setText("Ready")

        asset_count = len(self.current_assets.get("nodes", [])) if isinstance(self.current_assets, dict) else 0
        edge_count = len(self.current_assets.get("edges", [])) if isinstance(self.current_assets, dict) else 0
        evidence_count = len(self.current_evidence.get("items", [])) if isinstance(self.current_evidence, dict) else 0
        self.exposure_label.setText(
            f"Exposure map: {asset_count} assets / {edge_count} relations / {evidence_count} evidence items"
        )

    def _display_path(self, path: Path, max_parts: int = 4) -> str:
        parts = path.parts
        if len(parts) <= max_parts:
            return str(path)
        return str(Path("...").joinpath(*parts[-max_parts:]))

    def _target_output_name(self) -> str:
        target = self.target_input.text().strip()
        parsed = urlparse(target if "://" in target else f"//{target}")
        return parsed.hostname or target.rstrip("/").split("/")[0]

    def _report_path(self) -> Path:
        target = self._target_output_name()
        return self.output_dir / target / f"{target}_report.md"

    def _attack_plan_path(self) -> Path:
        target = self._target_output_name()
        return self.output_dir / target / f"{target}_attack_plan.md"

    def _summary_path(self) -> Path:
        target = self._target_output_name()
        return self.output_dir / target / f"{target}_summary.json"

    def _load_findings(self, findings: list[dict]):
        self.findings_table.setSortingEnabled(False)
        ordered = sorted(findings, key=lambda item: int(item.get("risk_score") or 0), reverse=True)
        self.findings_table.setRowCount(len(ordered))
        for row, finding in enumerate(ordered):
            values = [
                finding.get("id", ""),
                finding.get("priority", ""),
                finding.get("severity", ""),
                str(finding.get("risk_score", "")),
                finding.get("confidence", ""),
                finding.get("title", ""),
                finding.get("category", ""),
                ", ".join(finding.get("asset_keys", [])[:3]),
            ]
            for col, value in enumerate(values):
                item = QTableWidgetItem(value)
                if col == 3:
                    item.setData(Qt.UserRole, int(value or 0))
                self.findings_table.setItem(row, col, item)
        self.findings_table.setSortingEnabled(True)

    def _load_assets(self, assets: list[dict]):
        self.assets_table.setRowCount(len(assets))
        for row, asset in enumerate(assets):
            values = [
                asset.get("type", ""),
                asset.get("value", ""),
                asset.get("confidence", ""),
                ", ".join(asset.get("sources", [])),
            ]
            for col, value in enumerate(values):
                self.assets_table.setItem(row, col, QTableWidgetItem(value))

    def _load_modules(self, module: dict):
        latest_runs = {}
        for run in module.get("runs", []):
            latest_runs[run.get("module_id", "")] = run
        skipped = {
            item.get("module_id"): item.get("reason", "")
            for item in module.get("skipped", [])
            if isinstance(item, dict)
        }
        blocked = {
            item.get("module_id"): item.get("reason", "")
            for item in module.get("blocked", [])
            if isinstance(item, dict)
        }
        completed = set(module.get("completed", []))
        self.modules_table.setSortingEnabled(False)
        module_ids = get_all_module_ids()
        self.modules_table.setRowCount(len(module_ids))
        for row, module_id in enumerate(module_ids):
            entry = MODULE_REGISTRY[module_id]
            run = latest_runs.get(module_id, {})
            status = run.get("status", "")
            if not status:
                if module_id in completed:
                    status = "completed"
                elif module_id in skipped:
                    status = "skipped"
                elif module_id in blocked:
                    status = "blocked"
                else:
                    status = "pending"
            values = [
                str(entry.get("stage", "")),
                module_id,
                status,
                entry.get("detectability", ""),
                str(run.get("requests", 0)),
                str(run.get("assets_added", 0)),
                str(run.get("findings_added", 0)),
                run.get("error") or skipped.get(module_id) or blocked.get(module_id) or "",
            ]
            for col, value in enumerate(values):
                item = QTableWidgetItem(value)
                if col in (0, 4, 5, 6):
                    item.setData(Qt.UserRole, int(value or 0))
                self.modules_table.setItem(row, col, item)
        self.modules_table.setSortingEnabled(True)

    def _load_evidence(self, items: list[dict]):
        self.evidence_table.setRowCount(len(items))
        for row, item in enumerate(items):
            values = [
                item.get("id", ""),
                item.get("module_id", ""),
                item.get("type", ""),
                str(item.get("subject", "")),
                item.get("path", ""),
            ]
            for col, value in enumerate(values):
                self.evidence_table.setItem(row, col, QTableWidgetItem(value))

    def _load_submissions(self):
        target = self._target_output_name()
        submission_dir = self.output_dir / target / "submissions"
        files = sorted(submission_dir.glob("*.md")) if submission_dir.exists() else []
        self.submissions_table.setRowCount(len(files))
        for row, path in enumerate(files):
            values = [path.name, str(path.stat().st_size), str(path)]
            for col, value in enumerate(values):
                self.submissions_table.setItem(row, col, QTableWidgetItem(value))

    def _load_summary_json(self, summary: dict):
        if summary:
            self.summary_json.setPlainText(json.dumps(summary, indent=2, default=str))
        else:
            self.summary_json.setPlainText("No summary JSON generated yet.")

    def _load_settings_form(self):
        config = self._read_config()
        llm = config.get("llm", {})
        if hasattr(self, "llm_model_combo"):
            self.llm_model_combo.setCurrentText(str(llm.get("model", "")))
            self.llm_api_key_input.setText(str(llm.get("api_key", "")))
            self.llm_temperature_spin.setValue(float(llm.get("temperature", 0.1) or 0.1))
            self.llm_max_tokens_spin.setValue(int(llm.get("max_tokens", 2000) or 2000))

        target = config.get("target", {})
        if hasattr(self, "config_target_domain_input"):
            self.config_target_domain_input.setText(str(target.get("domain", "")))
            scope = target.get("scope", [])
            if isinstance(scope, str):
                scope = [scope]
            self.config_scope_input.setPlainText("\n".join(str(item) for item in scope if item is not None))
            self._set_combo_value(self.config_authorization_combo, str(target.get("authorization", "pending")))
            self._set_combo_value(self.config_mode_combo, str(target.get("mode", "passive")))

        detectability = config.get("detectability", {})
        if hasattr(self, "config_default_detectability_combo"):
            self._set_combo_value(
                self.config_default_detectability_combo,
                str(detectability.get("default", "low")),
            )
            self.config_allow_high_check.setChecked(bool(detectability.get("allow_high", False)))

        modules = config.get("modules", {})
        if hasattr(self, "config_auto_run_check"):
            self.config_auto_run_check.setChecked(bool(modules.get("auto_run", True)))
            self.config_skip_on_waf_check.setChecked(bool(modules.get("skip_on_waf", True)))
            self.config_record_http_evidence_check.setChecked(bool(modules.get("record_http_evidence", True)))
            self.config_max_empty_spin.setValue(int(modules.get("max_consecutive_empty", 5) or 0))

        rate_limits = config.get("rate_limits", {})
        if hasattr(self, "rate_limit_inputs"):
            for name, fields in self.rate_limit_inputs.items():
                values = rate_limits.get(name, {})
                fields["concurrent"].setValue(int(values.get("concurrent", 1) or 1))
                fields["per_minute"].setValue(int(values.get("per_minute", 60) or 60))

        api_keys = config.get("api_keys", {})
        if hasattr(self, "api_key_inputs"):
            for service, key_input in self.api_key_inputs.items():
                key_input.setText(str(api_keys.get(service, "")))

        auth = config.get("auth", {})
        if hasattr(self, "auth_bearer_input"):
            self.auth_bearer_input.setText(str(auth.get("bearer_token", "")))
            self.auth_cookie_input.setText(str(auth.get("cookie", "")))
            self.auth_headers_input.setPlainText(self._headers_to_text(auth.get("headers", {})))
            self.auth_probe_backoff_spin.setValue(int(auth.get("probe_backoff_seconds", 10) or 0))

        xss = config.get("xss", {})
        if hasattr(self, "xss_browser_confirm_check"):
            self.xss_browser_confirm_check.setChecked(bool(xss.get("browser_confirm", True)))
            self.xss_max_points_spin.setValue(int(xss.get("max_points", 80) or 80))
            self.xss_dalfox_timeout_spin.setValue(int(xss.get("dalfox_timeout", 600) or 600))

        nuclei = config.get("nuclei", {})
        if hasattr(self, "nuclei_full_cve_check"):
            self.nuclei_full_cve_check.setChecked(bool(nuclei.get("full_cve_on_confirmed_apex", True)))

        fast_scan = config.get("fast_scan", {})
        if hasattr(self, "fast_scan_paths_input"):
            self.fast_scan_paths_input.setPlainText(self._list_to_text(fast_scan.get("paths", [])))
            self.fast_scan_timeout_spin.setValue(int(fast_scan.get("timeout", 4) or 4))
            self.fast_scan_concurrency_spin.setValue(int(fast_scan.get("concurrency", 8) or 8))
            self.fast_scan_max_paths_spin.setValue(int(fast_scan.get("max_paths", 20) or 20))

        oob = config.get("oob", {})
        if hasattr(self, "oob_callback_domain_input"):
            self.oob_callback_domain_input.setText(str(oob.get("callback_domain", "")))
            self.oob_server_url_input.setText(str(oob.get("server_url", "")))
            self.oob_poll_url_input.setText(str(oob.get("poll_url", "")))
            self.oob_token_input.setText(str(oob.get("token", "")))
            self.oob_poll_interval_spin.setValue(int(oob.get("poll_interval", 2) or 2))
            self.oob_poll_timeout_spin.setValue(int(oob.get("poll_timeout", 30) or 30))

        self._load_raw_config_editor()
        self._load_tools_requirements_preview()
        self._refresh_key_status()
        self._refresh_tools_status()
        self._update_operation_context()

    def _save_settings_form(self):
        config = self._read_config()

        if hasattr(self, "llm_model_combo"):
            config.setdefault("llm", {})
            config["llm"].update({
                "model": self.llm_model_combo.currentText().strip(),
                "api_key": self.llm_api_key_input.text().strip(),
                "temperature": self.llm_temperature_spin.value(),
                "max_tokens": self.llm_max_tokens_spin.value(),
            })

        if hasattr(self, "config_target_domain_input"):
            config.setdefault("target", {})
            config["target"].update({
                "domain": self.config_target_domain_input.text().strip(),
                "scope": [
                    line.strip()
                    for line in self.config_scope_input.toPlainText().splitlines()
                    if line.strip()
                ],
                "authorization": self.config_authorization_combo.currentText(),
                "mode": self.config_mode_combo.currentText(),
            })

        if hasattr(self, "config_default_detectability_combo"):
            config.setdefault("detectability", {})
            config["detectability"].update({
                "default": self.config_default_detectability_combo.currentText(),
                "allow_high": self.config_allow_high_check.isChecked(),
            })

        if hasattr(self, "config_auto_run_check"):
            config.setdefault("modules", {})
            config["modules"].update({
                "auto_run": self.config_auto_run_check.isChecked(),
                "skip_on_waf": self.config_skip_on_waf_check.isChecked(),
                "max_consecutive_empty": self.config_max_empty_spin.value(),
                "record_http_evidence": self.config_record_http_evidence_check.isChecked(),
            })

        if hasattr(self, "rate_limit_inputs"):
            config.setdefault("rate_limits", {})
            for name, fields in self.rate_limit_inputs.items():
                config["rate_limits"][name] = {
                    "concurrent": fields["concurrent"].value(),
                    "per_minute": fields["per_minute"].value(),
                }

        if hasattr(self, "api_key_inputs"):
            config.setdefault("api_keys", {})
            for service, key_input in self.api_key_inputs.items():
                config["api_keys"][service] = key_input.text().strip()

        if hasattr(self, "auth_bearer_input"):
            config.setdefault("auth", {})
            config["auth"].update({
                "headers": self._text_to_headers(self.auth_headers_input.toPlainText()),
                "cookie": self.auth_cookie_input.text().strip(),
                "bearer_token": self.auth_bearer_input.text().strip(),
                "probe_backoff_seconds": self.auth_probe_backoff_spin.value(),
            })

        if hasattr(self, "xss_browser_confirm_check"):
            config.setdefault("xss", {})
            config["xss"].update({
                "browser_confirm": self.xss_browser_confirm_check.isChecked(),
                "max_points": self.xss_max_points_spin.value(),
                "dalfox_timeout": self.xss_dalfox_timeout_spin.value(),
            })

        if hasattr(self, "nuclei_full_cve_check"):
            config.setdefault("nuclei", {})
            config["nuclei"].update({
                "full_cve_on_confirmed_apex": self.nuclei_full_cve_check.isChecked(),
            })

        if hasattr(self, "fast_scan_paths_input"):
            config.setdefault("fast_scan", {})
            config["fast_scan"].update({
                "paths": self._text_to_list(self.fast_scan_paths_input.toPlainText()),
                "timeout": self.fast_scan_timeout_spin.value(),
                "concurrency": self.fast_scan_concurrency_spin.value(),
                "max_paths": self.fast_scan_max_paths_spin.value(),
            })

        if hasattr(self, "oob_callback_domain_input"):
            config.setdefault("oob", {})
            config["oob"].update({
                "callback_domain": self.oob_callback_domain_input.text().strip(),
                "server_url": self.oob_server_url_input.text().strip(),
                "poll_url": self.oob_poll_url_input.text().strip(),
                "token": self.oob_token_input.text().strip(),
                "poll_interval": self.oob_poll_interval_spin.value(),
                "poll_timeout": self.oob_poll_timeout_spin.value(),
            })

        if self._write_config(config):
            self._load_raw_config_editor()
            self._refresh_key_status()
            self._refresh_tools_status()
            self._update_operation_context()
            self.status_label.setText("Settings saved")

    def _load_raw_config_editor(self):
        if not hasattr(self, "raw_config_editor"):
            return
        if self.config_path.exists():
            self.raw_config_editor.setPlainText(self.config_path.read_text(errors="replace"))
        else:
            self.raw_config_editor.setPlainText("")

    def _save_raw_config_editor(self):
        text = self.raw_config_editor.toPlainText()
        try:
            parsed = yaml.safe_load(text) or {}
        except yaml.YAMLError as exc:
            QMessageBox.warning(self, "Invalid YAML", str(exc))
            return
        if not isinstance(parsed, dict):
            QMessageBox.warning(self, "Invalid YAML", "Config root must be a mapping.")
            return
        try:
            self.config_path.write_text(text)
        except OSError as exc:
            QMessageBox.warning(self, "Save Failed", str(exc))
            return
        self._load_settings_form()
        self.status_label.setText("Raw config applied")

    def _write_config(self, config: dict) -> bool:
        try:
            self.config_path.write_text(yaml.safe_dump(config, sort_keys=False))
            return True
        except OSError as exc:
            QMessageBox.warning(self, "Save Failed", str(exc))
            return False

    def _set_combo_value(self, combo: QComboBox, value: str):
        index = combo.findText(value)
        if index >= 0:
            combo.setCurrentIndex(index)
        elif combo.isEditable():
            combo.setCurrentText(value)

    def _headers_to_text(self, headers: dict) -> str:
        if not isinstance(headers, dict):
            return ""
        return "\n".join(f"{key}: {value}" for key, value in headers.items())

    def _text_to_headers(self, text: str) -> dict:
        headers = {}
        for line in text.splitlines():
            line = line.strip()
            if not line or ":" not in line:
                continue
            key, value = line.split(":", 1)
            key = key.strip()
            value = value.strip()
            if key and value:
                headers[key] = value
        return headers

    def _list_to_text(self, value) -> str:
        if isinstance(value, str):
            items = [item.strip() for item in value.split(",")]
        else:
            items = [str(item).strip() for item in (value or [])]
        return "\n".join(item for item in items if item)

    def _text_to_list(self, text: str) -> list[str]:
        items = []
        for line in text.replace(",", "\n").splitlines():
            item = line.strip()
            if item:
                items.append(item)
        return items

    def _open_evidence_cell(self, row: int, _col: int):
        item = self.evidence_table.item(row, 4)
        if not item:
            return
        path = self.output_dir / self._target_output_name() / item.text()
        if path.exists():
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(path)))

    def _open_submission_cell(self, row: int, _col: int):
        item = self.submissions_table.item(row, 2)
        if item and Path(item.text()).exists():
            QDesktopServices.openUrl(QUrl.fromLocalFile(item.text()))

    def refresh_graph(self):
        self._load_graph(self.current_assets)

    def _load_graph(self, assets: dict):
        graph = build_display_graph(
            assets,
            aggregate=self.graph_aggregate_check.isChecked(),
            aggregate_threshold=10,
        )
        nodes = graph["nodes"]
        edges = graph["edges"]
        meta = graph.get("meta", {})
        raw_nodes = meta.get("raw_nodes", len(nodes))
        raw_edges = meta.get("raw_edges", len(edges))
        self.graph_summary.setText(
            f"{raw_nodes} assets, {raw_edges} relations -> "
            f"{len(nodes)} displayed nodes, {len(edges)} displayed relations"
        )

        if not nodes:
            self.graph_view.setHtml(
                "<html><body style='font-family:Arial;background:#eef2f7;"
                "padding:24px;color:#334155;'>No asset graph available yet</body></html>"
            )
            return

        html = render_gravis_html(
            graph,
            show_labels=self.graph_labels_check.isChecked(),
            show_edges=self.graph_edges_check.isChecked(),
            height=max(640, self.graph_view.height() - 20),
        )
        self.graph_view.setHtml(html, QUrl.fromLocalFile(str(ROOT_DIR)))

    def _read_json(self, path: Path, default):
        if not path.exists():
            return default
        try:
            return json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            return default

    def _read_config(self) -> dict:
        if not self.config_path.exists():
            return {}
        try:
            return yaml.safe_load(self.config_path.read_text()) or {}
        except (yaml.YAMLError, OSError):
            return {}

    def _refresh_key_status(self):
        vault = KeyVault(self._read_config())
        presence = vault.presence()
        self.keys_table.setRowCount(len(presence))
        for row, (service, info) in enumerate(presence.items()):
            values = [
                info.get("label", service),
                "yes" if info.get("present") else "no",
                info.get("masked", ""),
            ]
            for col, value in enumerate(values):
                self.keys_table.setItem(row, col, QTableWidgetItem(value))

    def _refresh_tools_status(self):
        if not hasattr(self, "tools_table"):
            return
        available = tools_available()
        rows = sorted(TOOL_PRIORITIES.items(), key=lambda item: (item[1][0] != "minimum", item[0]))
        self.tools_table.setRowCount(len(rows))
        for row, (tool, (priority, purpose)) in enumerate(rows):
            ready = available.get(tool)
            if ready is None:
                ready = shutil.which(tool) is not None
            values = [tool, "yes" if ready else "no", priority, purpose]
            for col, value in enumerate(values):
                self.tools_table.setItem(row, col, QTableWidgetItem(value))

    def _load_tools_requirements_preview(self):
        if not hasattr(self, "tools_requirements_preview"):
            return
        if TOOLS_REQUIREMENTS.exists():
            self.tools_requirements_preview.setPlainText(
                TOOLS_REQUIREMENTS.read_text(errors="replace")
            )
        else:
            self.tools_requirements_preview.setPlainText("tools_requirements.txt not found.")

    def open_tools_requirements(self):
        if not TOOLS_REQUIREMENTS.exists():
            QMessageBox.information(self, "Missing File", "tools_requirements.txt does not exist.")
            return
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(TOOLS_REQUIREMENTS)))

    def _qt_environment(self, env: dict):
        from PySide6.QtCore import QProcessEnvironment

        process_env = QProcessEnvironment()
        for key, value in env.items():
            process_env.insert(key, value)
        return process_env

    def _apply_style(self):
        self.setStyleSheet("""
            QMainWindow, QWidget {
                background: #090d13;
                color: #dce7f3;
                font-size: 13px;
            }
            #title {
                color: #f8fafc;
                font-size: 21px;
                font-weight: 700;
                letter-spacing: 0px;
            }
            #subtitle {
                color: #7f8ea3;
                font-size: 12px;
            }
            #status {
                color: #ffccd2;
                padding: 7px 12px;
                border: 1px solid #7f1d1d;
                border-radius: 4px;
                background: #2a0f16;
                font-weight: 700;
            }
            #sidePanel, #sideScroll, QGroupBox, QTabWidget::pane {
                background: #101721;
                border: 1px solid #223044;
                border-radius: 6px;
            }
            #sideScroll {
                border: 0;
            }
            QScrollArea > QWidget > QWidget {
                background: #101721;
            }
            QScrollBar:vertical {
                background: #0b111a;
                width: 10px;
                margin: 0;
            }
            QScrollBar::handle:vertical {
                background: #334155;
                border-radius: 4px;
                min-height: 28px;
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                height: 0;
            }
            QGroupBox {
                margin-top: 10px;
                padding: 10px;
                font-weight: 600;
                color: #f1f5f9;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 4px;
                color: #ff6b7a;
                background: #101721;
            }
            QLineEdit, QComboBox, QPlainTextEdit, QTextEdit, QTableWidget {
                background: #0b111a;
                border: 1px solid #29384d;
                border-radius: 4px;
                color: #e5edf6;
                padding: 5px;
                selection-background-color: #9f1239;
            }
            QHeaderView::section {
                background: #151f2e;
                border: 0;
                border-right: 1px solid #26364c;
                color: #9fb0c5;
                padding: 6px;
                font-weight: 700;
            }
            QTableWidget::item {
                border-bottom: 1px solid #172233;
                padding: 4px;
            }
            QTabBar::tab {
                background: #0d1420;
                color: #9fb0c5;
                border: 1px solid #26364c;
                padding: 7px 10px;
                min-width: 70px;
            }
            QTabBar::tab:selected {
                background: #7f1d1d;
                color: #ffffff;
                border-color: #ef4444;
            }
            QCheckBox {
                color: #cbd5e1;
                spacing: 8px;
            }
            QCheckBox::indicator {
                width: 16px;
                height: 16px;
                border: 1px solid #40516b;
                border-radius: 3px;
                background: #0b111a;
            }
            QCheckBox::indicator:checked {
                background: #be123c;
                border-color: #fb7185;
            }
            QPushButton {
                background: #7f1d1d;
                color: #ffffff;
                border: 1px solid #ef4444;
                border-radius: 4px;
                padding: 8px 10px;
                font-weight: 600;
                min-width: 0;
            }
            QPushButton:disabled {
                background: #273244;
                border-color: #334155;
                color: #748299;
            }
            QPushButton:hover:!disabled {
                background: #9f1239;
            }
            #opsStrip {
                background: #101721;
                border: 1px solid #223044;
                border-left: 3px solid #ef4444;
                border-radius: 6px;
            }
            #opsPrimary {
                color: #f8fafc;
                font-size: 15px;
                font-weight: 700;
            }
            #opsSecondary {
                color: #91a2b8;
            }
            #opsState {
                color: #fecdd3;
                background: #2a0f16;
                border: 1px solid #7f1d1d;
                border-radius: 4px;
                padding: 9px 12px;
                font-weight: 700;
            }
            QProgressBar {
                background: #0b111a;
                border: 1px solid #29384d;
                border-radius: 4px;
                color: #dce7f3;
                text-align: center;
                min-height: 20px;
            }
            QProgressBar::chunk {
                background: #be123c;
                border-radius: 3px;
            }
            #metricCard {
                background: #0d1420;
                border: 1px solid #26364c;
                border-radius: 6px;
            }
            #metricCard[tone="danger"] {
                border-color: #7f1d1d;
            }
            #metricCard[tone="warning"] {
                border-color: #92400e;
            }
            #metricCard[tone="success"] {
                border-color: #166534;
            }
            #metricLabel {
                color: #7f8ea3;
                font-size: 10px;
                font-weight: 700;
            }
            #metricValue {
                color: #f8fafc;
                font-size: 18px;
                font-weight: 800;
            }
            #assistantStatus {
                color: #fecdd3;
                background: #2a0f16;
                border: 1px solid #7f1d1d;
                border-radius: 4px;
                padding: 8px;
            }
            #assistantStatus[ready="true"] {
                color: #bbf7d0;
                background: #0f2318;
                border-color: #166534;
            }
        """)


def main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
