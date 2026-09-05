import os
import socket
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List

from config import APP_NAME, APP_VERSION, BASE_DIR, QUARANTINE_DIR


REPORTS_DIR = BASE_DIR / "reports"


class ReportGenerator:
    def __init__(self):
        self.report_data: Dict[str, Any] = {
            "generated_at": "",
            "hostname": socket.gethostname(),
            "app_name": APP_NAME,
            "app_version": APP_VERSION,
            "score": 100,
            "sections": []
        }

    def add_section(self, title: str, status: str, items: List[Dict[str, str]], deduction: int = 0):
        self.report_data["sections"].append({
            "title": title,
            "status": status,
            "items": items,
            "deduction": deduction
        })
        self.report_data["score"] = max(0, self.report_data["score"] - deduction)

    def _score_color(self) -> str:
        s = self.report_data["score"]
        if s >= 80:
            return "#22c55e"
        elif s >= 50:
            return "#eab308"
        return "#ef4444"

    def _score_label(self) -> str:
        s = self.report_data["score"]
        if s >= 80:
            return "GUVENLI"
        elif s >= 50:
            return "RISKLI"
        return "TEHLIKELI"

    def _status_badge(self, status: str) -> str:
        colors = {
            "ok": ("#22c55e", "TEMIZ"),
            "warning": ("#eab308", "UYARI"),
            "danger": ("#ef4444", "TEHLIKE"),
            "info": ("#3b82f6", "BILGI"),
        }
        color, label = colors.get(status, ("#6b7280", status.upper()))
        return f'<span style="background:{color};color:#fff;padding:2px 10px;border-radius:4px;font-size:13px;font-weight:600">{label}</span>'

    def generate_html(self) -> str:
        self.report_data["generated_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        score = self.report_data["score"]
        score_color = self._score_color()
        score_label = self._score_label()

        sections_html = ""
        for sec in self.report_data["sections"]:
            items_html = ""
            for item in sec["items"]:
                severity = item.get("severity", "")
                sev_dot = ""
                if severity == "HIGH":
                    sev_dot = '<span style="color:#ef4444">&#9679;</span> '
                elif severity == "MEDIUM":
                    sev_dot = '<span style="color:#eab308">&#9679;</span> '

                items_html += f"""
                <tr>
                    <td style="padding:8px 12px;border-bottom:1px solid #1e293b">{sev_dot}{item.get('label', '')}</td>
                    <td style="padding:8px 12px;border-bottom:1px solid #1e293b;color:#94a3b8">{item.get('value', '')}</td>
                </tr>"""

            sections_html += f"""
            <div style="background:#0f172a;border-radius:8px;padding:20px;margin-bottom:16px">
                <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
                    <h3 style="margin:0;color:#e2e8f0;font-size:16px">{sec['title']}</h3>
                    {self._status_badge(sec['status'])}
                </div>
                <table style="width:100%;border-collapse:collapse">
                    {items_html}
                </table>
            </div>"""

        quarantine_count = 0
        manifest = QUARANTINE_DIR / "quarantine_manifest.json"
        if manifest.exists():
            try:
                with open(manifest, "r", encoding="utf-8") as f:
                    quarantine_count = len(json.load(f))
            except Exception:
                pass

        html = f"""<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{APP_NAME} - Guvenlik Raporu</title>
    <style>
        * {{ margin:0; padding:0; box-sizing:border-box; }}
        body {{ background:#020617; color:#e2e8f0; font-family:'Segoe UI',system-ui,-apple-system,sans-serif; padding:30px; }}
        .container {{ max-width:800px; margin:0 auto; }}
        .header {{ text-align:center; margin-bottom:30px; padding:30px; background:linear-gradient(135deg,#0f172a 0%,#1e293b 100%); border-radius:12px; border:1px solid #334155; }}
        .score-ring {{ width:120px; height:120px; border-radius:50%; border:6px solid {score_color}; display:flex; flex-direction:column; align-items:center; justify-content:center; margin:20px auto; }}
        .score-num {{ font-size:36px; font-weight:700; color:{score_color}; }}
        .score-label {{ font-size:12px; color:{score_color}; font-weight:600; letter-spacing:1px; }}
        .footer {{ text-align:center; margin-top:30px; padding:16px; color:#475569; font-size:12px; }}
        .stats {{ display:flex; gap:12px; justify-content:center; margin-top:16px; }}
        .stat-box {{ background:#1e293b; padding:10px 18px; border-radius:8px; text-align:center; }}
        .stat-num {{ font-size:20px; font-weight:700; color:#38bdf8; }}
        .stat-lbl {{ font-size:11px; color:#64748b; margin-top:2px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1 style="font-size:22px;color:#38bdf8;margin-bottom:4px">&#128737; {APP_NAME}</h1>
            <p style="color:#64748b;font-size:13px">Guvenlik Raporu &mdash; {self.report_data['generated_at']}</p>

            <div class="score-ring">
                <div class="score-num">{score}</div>
                <div class="score-label">{score_label}</div>
            </div>

            <div class="stats">
                <div class="stat-box">
                    <div class="stat-num">{len(self.report_data['sections'])}</div>
                    <div class="stat-lbl">Tarama</div>
                </div>
                <div class="stat-box">
                    <div class="stat-num">{quarantine_count}</div>
                    <div class="stat-lbl">Karantina</div>
                </div>
                <div class="stat-box">
                    <div class="stat-num">{self.report_data['hostname']}</div>
                    <div class="stat-lbl">Bilgisayar</div>
                </div>
            </div>
        </div>

        {sections_html}

        <div class="footer">
            {APP_NAME} v{APP_VERSION} &bull; {self.report_data['generated_at']}
        </div>
    </div>
</body>
</html>"""
        return html

    def save_report(self) -> str:
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"report_{ts}.html"
        filepath = REPORTS_DIR / filename

        html = self.generate_html()
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html)

        return str(filepath)

