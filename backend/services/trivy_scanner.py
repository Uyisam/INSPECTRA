
import json
import os
import shutil
import subprocess
from pathlib import Path, PureWindowsPath
from urllib.parse import urlparse


SCAN_TIMEOUT = 300


def run_trivy_scan(target: str):
    """
    Run a Trivy vulnerability scan against a local filesystem
    target or a remote HTTPS Git repository.

    Supports Windows asset paths mapped into Docker.
    Returns parsed Trivy JSON results.
    """

    if not isinstance(target, str) or not target.strip():
        raise ValueError("Scan target must be a non-empty string.")

    target = target.strip()

    trivy_path = shutil.which("trivy")

    if not trivy_path:
        raise RuntimeError(
            "Trivy was not found. Install Trivy and ensure it is "
            "available in the system PATH."
        )

    parsed_url = urlparse(target)

    if parsed_url.scheme == "https" and parsed_url.netloc:
        if not parsed_url.path or parsed_url.path == "/":
            raise ValueError("Invalid remote repository URL.")

        command = [
            trivy_path,
            "repo",
            "--scanners", "vuln",
            "--format", "json",
            "--skip-dirs", "venv",
            "--skip-dirs", "frontend/node_modules",
            target
        ]

    else:
        scan_root = os.getenv("SCAN_ROOT")
        host_root = os.getenv("SCAN_HOST_ROOT")

        if scan_root and host_root:
            windows_target = PureWindowsPath(target)
            windows_root = PureWindowsPath(host_root)

            try:
                relative_target = windows_target.relative_to(
                    windows_root
                )
            except ValueError as error:
                raise ValueError(
                    f"Target is outside the mounted scan directory: {target}"
                ) from error

            root_path = Path(scan_root).resolve()
            local_target = root_path.joinpath(
                *relative_target.parts
            ).resolve()

            if not local_target.is_relative_to(root_path):
                raise ValueError(
                    "Scan target is outside the permitted scan directory."
                )
        else:
            local_target = Path(target).expanduser()

        if not local_target.exists():
            raise ValueError(
                f"Scan target does not exist: {target}"
            )

        if not (local_target.is_file() or local_target.is_dir()):
            raise ValueError(
                f"Scan target must be a file or directory: {target}"
            )

        command = [
            trivy_path,
            "fs",
            "--scanners", "vuln",
            "--format", "json",
            "--skip-dirs", "venv",
            "--skip-dirs", "frontend/node_modules",
            str(local_target)
        ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=SCAN_TIMEOUT,
            check=False
        )

    except subprocess.TimeoutExpired as error:
        raise RuntimeError(
            f"Trivy scan exceeded the {SCAN_TIMEOUT}-second timeout."
        ) from error

    except OSError as error:
        raise RuntimeError(
            f"Unable to execute Trivy: {error}"
        ) from error

    if result.returncode != 0:
        error_details = (
            result.stderr.strip()
            or result.stdout.strip()
            or "No error details were provided."
        )

        raise RuntimeError(
            f"Trivy scan failed with exit code "
            f"{result.returncode}: {error_details}"
        )

    if not result.stdout.strip():
        raise RuntimeError(
            "Trivy returned empty output."
        )

    try:
        scan_results = json.loads(result.stdout)

    except json.JSONDecodeError as error:
        raise RuntimeError(
            f"Trivy returned invalid JSON output: {error}"
        ) from error

    if not isinstance(scan_results, dict):
        raise RuntimeError(
            "Trivy returned an unexpected JSON structure."
        )

    return scan_results
