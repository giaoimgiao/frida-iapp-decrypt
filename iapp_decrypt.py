#!/usr/bin/env python3
"""
iApp Frida Decrypt Tool

A Frida-based tool for decrypting iApp framework scripts at runtime.

Usage:
    python iapp_decrypt.py -p com.example.app    # Spawn mode (recommended)
    python iapp_decrypt.py -a com.example.app    # Attach mode
    python iapp_decrypt.py -a 12345              # Attach by PID
"""

import argparse
import frida
import sys
import time
import os
import subprocess
from pathlib import Path

# Ensure real-time output
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(line_buffering=True)
    sys.stderr.reconfigure(line_buffering=True)

# Load hook script
SCRIPT_DIR = Path(__file__).parent
JS_PATH = SCRIPT_DIR / "iapp_hook.js"

def load_script():
    """Load the Frida hook script"""
    if not JS_PATH.exists():
        print(f"[!] Hook script not found: {JS_PATH}")
        sys.exit(1)
    return JS_PATH.read_text(encoding="utf-8")

def on_message(message, data):
    """Handle messages from Frida script"""
    if message["type"] == "send":
        print("[*] " + str(message["payload"]))
    elif message["type"] == "error":
        desc = message.get("description", message.get("stack", str(message)))
        print("[!] " + str(desc))
    else:
        print(str(message))

def get_device(timeout=10):
    """Get USB device with retry"""
    print("[*] Connecting to device...")
    try:
        device = frida.get_usb_device(timeout=timeout)
        print(f"[*] Connected: {device.name}")
        return device
    except frida.TimedOutError:
        print("[!] Device not found. Check USB connection and USB debugging.")
        sys.exit(1)

def find_adb():
    """Find adb executable"""
    # Check common locations
    locations = [
        "adb",
        "platform-tools/adb",
        os.path.expanduser("~/Android/Sdk/platform-tools/adb"),
        "C:\\Users\\%USERNAME%\\AppData\\Local\\Android\\Sdk\\platform-tools\\adb.exe",
    ]
    
    for loc in locations:
        loc = os.path.expandvars(loc)
        if os.path.exists(loc):
            return loc
        # Try which/where
        try:
            result = subprocess.run(
                ["where" if sys.platform == "win32" else "which", "adb"],
                capture_output=True, text=True
            )
            if result.returncode == 0:
                return result.stdout.strip().split('\n')[0]
        except:
            pass
    return "adb"  # Hope it's in PATH

def spawn_mode(package_name):
    """Run in spawn mode - start app fresh"""
    device = get_device()
    adb = find_adb()
    
    # Force stop app first
    print(f"[*] Stopping {package_name}...")
    subprocess.run([adb, "shell", f"am force-stop {package_name}"], 
                   capture_output=True)
    
    # Clear old output
    subprocess.run([adb, "shell", "rm -rf /data/local/tmp/iapp_out/*"],
                   capture_output=True)
    subprocess.run([adb, "shell", "mkdir -p /data/local/tmp/iapp_out"],
                   capture_output=True)
    time.sleep(0.5)
    
    # Spawn
    print(f"[*] Spawning {package_name}...")
    try:
        pid = device.spawn([package_name])
        print(f"[*] PID: {pid}")
    except frida.NotSupportedError as e:
        print(f"[!] Spawn failed: {e}")
        print("[!] Try: adb shell 'su -c setenforce 0'")
        sys.exit(1)
    
    # Attach and load script
    session = device.attach(pid)
    script = session.create_script(load_script())
    script.on("message", on_message)
    script.load()
    
    # Resume
    print("[*] Resuming app...")
    device.resume(pid)
    
    print("[*] Hooks active. Interact with the app to capture scripts.")
    print("[*] Press Ctrl+C to stop.\n")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Stopping...")
        session.detach()

def attach_mode(target):
    """Run in attach mode - attach to running app"""
    device = get_device()
    
    # Determine if target is PID or package name
    try:
        pid = int(target)
        print(f"[*] Attaching to PID {pid}...")
    except ValueError:
        print(f"[*] Finding process {target}...")
        try:
            pid = device.get_process(target).pid
            print(f"[*] Found PID: {pid}")
        except frida.ProcessNotFoundError:
            print(f"[!] Process not found: {target}")
            print("[!] Make sure the app is running.")
            sys.exit(1)
    
    # Attach
    session = device.attach(pid)
    script = session.create_script(load_script())
    script.on("message", on_message)
    script.load()
    
    print("[*] Hooks active. Interact with the app to capture scripts.")
    print("[*] Press Ctrl+C to stop.\n")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Stopping...")
        session.detach()

def pull_output(output_dir="./output"):
    """Pull decrypted files from device"""
    adb = find_adb()
    os.makedirs(output_dir, exist_ok=True)
    
    print(f"[*] Pulling files to {output_dir}...")
    result = subprocess.run(
        [adb, "pull", "/data/local/tmp/iapp_out/", output_dir],
        capture_output=True, text=True
    )
    
    if result.returncode == 0:
        print("[*] Done!")
        # List files
        for f in Path(output_dir).rglob("*"):
            if f.is_file():
                print(f"    {f.name} ({f.stat().st_size} bytes)")
    else:
        print(f"[!] Pull failed: {result.stderr}")

def main():
    parser = argparse.ArgumentParser(
        description="iApp Frida Decrypt Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    %(prog)s -p com.example.app       Spawn and hook app
    %(prog)s -a com.example.app       Attach to running app
    %(prog)s -a 12345                 Attach by PID
    %(prog)s --pull                   Pull decrypted files
        """
    )
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-p", "--spawn", metavar="PACKAGE",
                       help="Spawn app (recommended)")
    group.add_argument("-a", "--attach", metavar="TARGET",
                       help="Attach to running app (package name or PID)")
    group.add_argument("--pull", action="store_true",
                       help="Pull decrypted files from device")
    
    parser.add_argument("-o", "--output", default="./output",
                        help="Output directory for --pull (default: ./output)")
    
    args = parser.parse_args()
    
    if args.pull:
        pull_output(args.output)
    elif args.spawn:
        spawn_mode(args.spawn)
    elif args.attach:
        attach_mode(args.attach)

if __name__ == "__main__":
    main()
