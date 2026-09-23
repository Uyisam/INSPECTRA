import json
import subprocess


def run_trivy_scan(target: str):
    """
    Run a Trivy vulnerability scan against a local target
    and return the JSON results.
    """

    command = [
        "trivy",
        "fs",
        "--scanners", "vuln",
        "--format", "json",
        "--skip-dirs", "venv",
        "--skip-dirs", "frontend/node_modules",
        target
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=300
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"Trivy scan failed: {result.stderr}"
        )

    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError(
            f"Could not read Trivy JSON output: {error}"
        )