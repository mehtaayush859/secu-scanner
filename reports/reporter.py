"""
Reporting Module for SecuScan

Generates scan reports in JSON, HTML, and PDF formats.
"""

import json
import os
import datetime
from typing import Dict, Any
from jinja2 import Environment, FileSystemLoader

REPORTS_DIR = os.environ.get("SECUAUTH_REPORTS_DIR", os.path.abspath(os.path.join(os.path.dirname(__file__), "html")))
TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), "templates")

def generate_report(results: Dict[str, Any], output_format: str, report_filename: str = None) -> None:
    """
    Generate a report from scan results.

    Args:
        results (Dict[str, Any]): Scan results.
        output_format (str): 'json', 'html', or 'pdf'.
        report_filename (str, optional): Custom report filename. Defaults to None.

    Example:
        generate_report({"ports": [...]}, "json")
    """
    os.makedirs(REPORTS_DIR, exist_ok=True)
    if not report_filename:
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        report_filename = f"scan_report_{timestamp}.{output_format}"
    path = os.path.join(REPORTS_DIR, report_filename)
    if output_format == "json":
        with open(path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
        print(f"[+] JSON report saved to {path}")

    elif output_format == "html":
        env = Environment(loader=FileSystemLoader(TEMPLATES_DIR))
        template = env.get_template("report_template.html")
        html_content = template.render(
            results=results,
            now=lambda: datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )
        with open(path, "w", encoding="utf-8") as f:
            f.write(html_content)
        print(f"[+] HTML report saved to {path}")
    else:
        print("[-] Unknown report format.")