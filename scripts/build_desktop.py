#!/usr/bin/env python3
"""Build the Docspector single-file desktop executable.

Inspect. Verify. Trust.

Steps:
1. Build the React frontend (Vite) unless --skip-frontend is given.
2. Bundle the FastAPI backend, the built frontend, and a Python runtime
   into ONE self-contained executable with PyInstaller.

Output: backend/dist/Docspector.exe (Windows) or backend/dist/Docspector
(Linux/macOS). The executable needs no Python, Node, or archive extraction
on the target machine — double-click and the app opens in the browser.

Usage:
    python scripts/build_desktop.py                 # full build
    python scripts/build_desktop.py --skip-frontend # reuse frontend/dist
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
FRONTEND_DIR = REPO_ROOT / "frontend"
BACKEND_DIR = REPO_ROOT / "backend"
FRONTEND_DIST = FRONTEND_DIR / "dist"
EXE_BASENAME = "Docspector"


def run(cmd: list[str], cwd: Path) -> None:
    print(f"\n>> {' '.join(str(part) for part in cmd)}  [cwd={cwd}]", flush=True)
    subprocess.run([str(part) for part in cmd], cwd=str(cwd), check=True)


def build_frontend() -> None:
    npm = shutil.which("npm")
    if npm is None:
        sys.exit("ERROR: npm not found on PATH; install Node.js 18+ first.")
    if not (FRONTEND_DIR / "node_modules").is_dir():
        run([npm, "ci", "--no-audit", "--no-fund"], FRONTEND_DIR)
    run([npm, "run", "build"], FRONTEND_DIR)


def build_executable(python_exe: str) -> Path:
    run(
        [python_exe, "-m", "pip", "install", "--quiet", "pyinstaller>=6.10"],
        BACKEND_DIR,
    )

    add_data = f"{FRONTEND_DIST}{os.pathsep}frontend_dist"
    run(
        [
            python_exe,
            "-m",
            "PyInstaller",
            "--noconfirm",
            "--clean",
            "--onefile",
            "--name",
            EXE_BASENAME,
            "--add-data",
            add_data,
            "--collect-submodules",
            "app",
            "--collect-submodules",
            "uvicorn",
            "--hidden-import",
            "python_multipart",
            "desktop.py",
        ],
        BACKEND_DIR,
    )

    exe_name = f"{EXE_BASENAME}.exe" if os.name == "nt" else EXE_BASENAME
    return BACKEND_DIR / "dist" / exe_name


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--skip-frontend",
        action="store_true",
        help="Reuse an existing frontend/dist build.",
    )
    parser.add_argument(
        "--python",
        default=sys.executable,
        help="Python interpreter to build with (defaults to current).",
    )
    args = parser.parse_args()

    if not args.skip_frontend:
        build_frontend()

    if not (FRONTEND_DIST / "index.html").is_file():
        sys.exit(
            "ERROR: frontend/dist/index.html not found. "
            "Run without --skip-frontend or build the frontend first."
        )

    exe_path = build_executable(args.python)
    if not exe_path.is_file():
        sys.exit(f"ERROR: expected output not found: {exe_path}")

    size_mb = exe_path.stat().st_size / (1024 * 1024)
    print(f"\nBuild complete: {exe_path} ({size_mb:.1f} MB)")


if __name__ == "__main__":
    main()
