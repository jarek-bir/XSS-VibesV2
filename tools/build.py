#!/usr/bin/env python3
"""
Build script for creating binary executables of XSS Vibes.
Supports multiple platforms and build options.
"""

import os
import sys
import shutil
import subprocess
from pathlib import Path


def check_pyinstaller():
    """Check if PyInstaller is installed."""
    try:
        import PyInstaller

        return True
    except ImportError:
        print("PyInstaller not found, installing...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller"])
        return True


def build_binary(
    script_name="main_modern.py",
    output_name="xss-vibes",
    icon_path=None,
    onefile=True,
    console=True,
    additional_files=None,
):
    """Build binary executable using PyInstaller."""

    if not check_pyinstaller():
        print("Failed to install PyInstaller")
        return False

    print(f"Building binary for {script_name}...")

    # Find pyinstaller executable
    pyinstaller_cmd = "pyinstaller"
    try:
        # Try to find pyinstaller in virtual environment
        import sys

        venv_pyinstaller = Path(sys.executable).parent / "pyinstaller"
        if venv_pyinstaller.exists():
            pyinstaller_cmd = str(venv_pyinstaller)
        else:
            # Use module approach
            pyinstaller_cmd = [sys.executable, "-m", "PyInstaller"]
    except Exception:
        pass

    # Base PyInstaller command
    if isinstance(pyinstaller_cmd, list):
        cmd = pyinstaller_cmd.copy()
    else:
        cmd = [pyinstaller_cmd]

    cmd.extend(
        [
            "--clean",
            "--noconfirm",
            f"--name={output_name}",
        ]
    )

    # Build options
    if onefile:
        cmd.append("--onefile")
    else:
        cmd.append("--onedir")

    if console:
        cmd.append("--console")
    else:
        cmd.append("--windowed")

    # Add icon if provided
    if icon_path and Path(icon_path).exists():
        cmd.extend(["--icon", icon_path])

    # Add additional files
    if additional_files:
        for src, dest in additional_files:
            cmd.extend(["--add-data", f"{src}{os.pathsep}{dest}"])

    # Hidden imports for our modules
    hidden_imports = [
        "requests",
        "aiohttp",
        "colorama",
        "json",
        "pathlib",
        "asyncio",
        "concurrent.futures",
        "urllib.parse",
        "urllib3",
        "ssl",
        "socket",
        "argparse",
    ]

    for imp in hidden_imports:
        cmd.extend(["--hidden-import", imp])

    # Add the main script
    cmd.append(script_name)

    print(f"Running: {' '.join(cmd)}")

    try:
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        print("Build successful!")
        print(f"Binary created in: dist/{output_name}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Build failed: {e}")
        print(f"Error output: {e.stderr}")
        return False


def create_spec_file():
    """Create a custom .spec file for advanced configuration."""

    spec_content = """# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

# Additional data files to include
added_files = [
    ('payloads.json', '.'),
    ('waf_payloads.json', '.'),
    ('waf_list.txt', '.'),
    ('requirements.txt', '.'),
    ('README_MODERN.md', '.'),
]

a = Analysis(
    ['main_modern.py'],
    pathex=[],
    binaries=[],
    datas=added_files,
    hiddenimports=[
        'requests',
        'aiohttp',
        'colorama', 
        'wafw00f',
        'json',
        'pathlib',
        'asyncio',
        'concurrent.futures',
        'urllib.parse',
        'argparse',
        'logging',
        'dataclasses',
        'enum',
        'typing'
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='xss-vibes',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
"""

    with open("xss-vibes.spec", "w") as f:
        f.write(spec_content)

    print("Created xss-vibes.spec file")


def build_all_variants():
    """Build multiple variants of the binary."""

    variants = [
        {
            "name": "xss-vibes",
            "script": "main_modern.py",
            "description": "Modern version with async support",
        },
        {
            "name": "xss-vibes-legacy",
            "script": "main.py",
            "description": "Legacy version for compatibility",
        },
    ]

    # Files to include with binary
    additional_files = [
        ("payloads.json", "."),
        ("waf_payloads.json", "."),
        ("waf_list.txt", "."),
        ("requirements.txt", "."),
        ("README_MODERN.md", "."),
    ]

    for variant in variants:
        print(f"\nBuilding {variant['name']} - {variant['description']}")

        if Path(variant["script"]).exists():
            success = build_binary(
                script_name=variant["script"],
                output_name=variant["name"],
                additional_files=additional_files,
            )

            if success:
                print(f"✅ {variant['name']} built successfully")
            else:
                print(f"❌ Failed to build {variant['name']}")
        else:
            print(f"⚠️  Script {variant['script']} not found, skipping")


def create_installer_script():
    """Create an installer script for the binary."""

    installer_content = """#!/bin/bash
# XSS Vibes Binary Installer

set -e

INSTALL_DIR="/usr/local/bin"
BINARY_NAME="xss-vibes"
CONFIG_DIR="$HOME/.xss-vibes"

echo "Installing XSS Vibes..."

# Create config directory
mkdir -p "$CONFIG_DIR"

# Copy binary
if [ -f "./dist/$BINARY_NAME" ]; then
    sudo cp "./dist/$BINARY_NAME" "$INSTALL_DIR/"
    sudo chmod +x "$INSTALL_DIR/$BINARY_NAME"
    echo "✅ Binary installed to $INSTALL_DIR/$BINARY_NAME"
else
    echo "❌ Binary not found. Please build first with: python build.py"
    exit 1
fi

# Copy configuration files
if [ -f "./payloads.json" ]; then
    cp "./payloads.json" "$CONFIG_DIR/"
    echo "✅ Payloads copied to $CONFIG_DIR/"
fi

if [ -f "./waf_list.txt" ]; then
    cp "./waf_list.txt" "$CONFIG_DIR/" 
    echo "✅ WAF list copied to $CONFIG_DIR/"
fi

# Create symlink for legacy version if available
if [ -f "./dist/xss-vibes-legacy" ]; then
    sudo cp "./dist/xss-vibes-legacy" "$INSTALL_DIR/"
    sudo chmod +x "$INSTALL_DIR/xss-vibes-legacy"
    echo "✅ Legacy version installed"
fi

echo ""
echo "🎉 Installation complete!"
echo "Usage: $BINARY_NAME -u 'http://example.com/?id=1'"
echo "Help:  $BINARY_NAME --help"
echo ""
echo "Configuration files are in: $CONFIG_DIR"
"""

    with open("install.sh", "w") as f:
        f.write(installer_content)

    os.chmod("install.sh", 0o755)
    print("Created install.sh script")


def create_windows_installer():
    """Create Windows installer script."""

    windows_installer = """@echo off
REM XSS Vibes Windows Installer

set INSTALL_DIR=%PROGRAMFILES%\\XSSVibes
set BINARY_NAME=xss-vibes.exe

echo Installing XSS Vibes...

REM Create install directory
if not exist "%INSTALL_DIR%" mkdir "%INSTALL_DIR%"

REM Copy binary
if exist ".\\dist\\%BINARY_NAME%" (
    copy ".\\dist\\%BINARY_NAME%" "%INSTALL_DIR%\\" >nul
    echo ✅ Binary installed to %INSTALL_DIR%
) else (
    echo ❌ Binary not found. Please build first with: python build.py
    pause
    exit /b 1
)

REM Copy configuration files
if exist ".\\payloads.json" (
    copy ".\\payloads.json" "%INSTALL_DIR%\\" >nul
    echo ✅ Payloads copied
)

if exist ".\\waf_list.txt" (
    copy ".\\waf_list.txt" "%INSTALL_DIR%\\" >nul
    echo ✅ WAF list copied
)

REM Add to PATH (requires admin)
echo Adding to system PATH...
setx PATH "%PATH%;%INSTALL_DIR%" /M >nul 2>&1
if %errorlevel% equ 0 (
    echo ✅ Added to system PATH
) else (
    echo ⚠️  Could not add to PATH. Run as administrator or add manually.
)

echo.
echo 🎉 Installation complete!
echo Usage: xss-vibes -u "http://example.com/?id=1"
echo Help:  xss-vibes --help
pause
"""

    with open("install.bat", "w") as f:
        f.write(windows_installer)

    print("Created install.bat script")


def clean_build():
    """Clean build artifacts."""

    dirs_to_clean = ["build", "dist", "__pycache__"]
    files_to_clean = ["*.spec"]

    for dir_name in dirs_to_clean:
        if Path(dir_name).exists():
            shutil.rmtree(dir_name)
            print(f"Removed {dir_name}/")

    import glob

    for pattern in files_to_clean:
        for file_path in glob.glob(pattern):
            Path(file_path).unlink()
            print(f"Removed {file_path}")


def main():
    """Main build function."""

    import argparse

    parser = argparse.ArgumentParser(description="Build XSS Vibes binary")
    parser.add_argument("--clean", action="store_true", help="Clean build artifacts")
    parser.add_argument("--spec", action="store_true", help="Create .spec file")
    parser.add_argument("--all", action="store_true", help="Build all variants")
    parser.add_argument(
        "--install-scripts", action="store_true", help="Create installer scripts"
    )
    parser.add_argument(
        "--modern-only", action="store_true", help="Build only modern version"
    )

    args = parser.parse_args()

    if args.clean:
        clean_build()
        return

    if args.spec:
        create_spec_file()
        return

    if args.install_scripts:
        create_installer_script()
        create_windows_installer()
        return

    if args.all:
        build_all_variants()
    elif args.modern_only:
        additional_files = [
            ("payloads.json", "."),
            ("waf_payloads.json", "."),
            ("waf_list.txt", "."),
            ("requirements.txt", "."),
            ("README_MODERN.md", "."),
        ]
        build_binary(
            script_name="main_modern.py",
            output_name="xss-vibes",
            additional_files=additional_files,
        )
    else:
        print("Use --help to see available options")
        print("Quick start: python build.py --modern-only")


if __name__ == "__main__":
    main()
