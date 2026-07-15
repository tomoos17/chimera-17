# recon.py — CHIMERA-17 Attacker: Reconnaissance Module
# First stage of the attack pipeline.
# Gathers intelligence on a target before any exploitation begins.
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import subprocess
import socket
import requests
from brain.state import ChimeraState, Finding


# nmap
def scan_ports(target, state):
    print(f"[RECON] Scanning ports on {target}...")
    
    try:
        result = subprocess.run(
            ["nmap", "-sV", "-O", target],
            capture_output=True,
            text=True,
            timeout=120
        )
        
        finding = Finding(
            source="sword",
            finding_type="info",
            severity="info",
            title=f"Port scan results for {target}",
            description=result.stdout,
            evidence=result.stdout
        )
        
        state.add_finding(finding)
        return result.stdout
        
    except Exception as e:
        print(f"[RECON] Scan failed: {e}")
        return None


# whois
def get_whois(target, state):
    print(f"[RECON] Running WHOIS on {target}...")
    
    try:
        result = subprocess.run(
            ["whois", target],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        finding = Finding(
            source="sword",
            finding_type="info",
            severity="info",
            title=f"WHOIS results for {target}",
            description=result.stdout,
            evidence=result.stdout
        )
        
        state.add_finding(finding)
        return result.stdout
        
    except Exception as e:
        print(f"[RECON] WHOIS failed: {e}")
        return None


# dns enumeration
def enumerate_dns(target, state):
    print(f"[RECON] Enumerating DNS for {target}...")
    
    try:
        result = subprocess.run(
            ["dig", target, "ANY"],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        # Also check for subdomains
        subdomains = ["www", "mail", "ftp", "admin", "vpn", "dev", "test"]
        found_subdomains = []
        
        for sub in subdomains:
            try:
                full_domain = f"{sub}.{target}"
                socket.gethostbyname(full_domain)
                found_subdomains.append(full_domain)
                print(f"[RECON] Found subdomain: {full_domain}")
            except socket.gaierror:
                pass
        
        description = result.stdout
        if found_subdomains:
            description += f"\nSubdomains found: {', '.join(found_subdomains)}"
        
        finding = Finding(
            source="sword",
            finding_type="info",
            severity="info",
            title=f"DNS enumeration for {target}",
            description=description,
            evidence=result.stdout
        )
        
        state.add_finding(finding)
        return {"dns": result.stdout, "subdomains": found_subdomains}
        
    except Exception as e:
        print(f"[RECON] DNS enumeration failed: {e}")
        return None
    
# smb enumeration
def enumerate_smb(target, state):
    print(f"[RECON] Enumerating SMB on {target}...")
    
    try:
        result = subprocess.run(
            ["nmap", "--script", "smb-enum-shares,smb-enum-users", "-p", "139,445", target],
            capture_output=True,
            text=True,
            timeout=120
        )
        
        finding = Finding(
            source="sword",
            finding_type="info",
            severity="medium",
            title=f"SMB enumeration for {target}",
            description=result.stdout,
            evidence=result.stdout
        )
        
        state.add_finding(finding)
        return result.stdout
        
    except Exception as e:
        print(f"[RECON] SMB enumeration failed: {e}")
        return None
    
# Anonymous login check
def check_anonymous_login(target, state):
    print(f"[RECON] Checking anonymous login on {target}...")
    
    try:
        # Check FTP anonymous login
        result = subprocess.run(
            ["nmap", "--script", "ftp-anon", "-p", "21", target],
            capture_output=True,
            text=True,
            timeout=60
        )
        
        anonymous_allowed = "Anonymous FTP login allowed" in result.stdout
        
        severity = "high" if anonymous_allowed else "info"
        
        finding = Finding(
            source="sword",
            finding_type="vulnerability" if anonymous_allowed else "info",
            severity=severity,
            title=f"Anonymous FTP login {'allowed' if anonymous_allowed else 'not allowed'} on {target}",
            description=result.stdout,
            evidence=result.stdout
        )
        
        state.add_finding(finding)
        return {"anonymous_allowed": anonymous_allowed, "details": result.stdout}
        
    except Exception as e:
        print(f"[RECON] Anonymous login check failed: {e}")
        return None
    
# banner grabbing
def grab_banners(target, state):
    print(f"[RECON] Grabbing service banners on {target}...")
    
    common_ports = [21, 22, 80, 443, 8080, 3306, 3389]
    banners = {}
    
    for port in common_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((target, port))
            banner = sock.recv(1024).decode().strip()
            banners[port] = banner
            print(f"[RECON] Port {port}: {banner}")
            sock.close()
            
        except:
            pass
    
    finding = Finding(
        source="sword",
        finding_type="info",
        severity="info",
        title=f"Service banners for {target}",
        description=str(banners),
        evidence=str(banners)
    )
    
    state.add_finding(finding)
    return banners

def run_recon(target, state):
    print(f"\n[RECON] Starting full reconnaissance on {target}")
    print("="*50)
    
    results = {}
    
    results["ports"] = scan_ports(target, state)
    results["whois"] = get_whois(target, state)
    results["dns"] = enumerate_dns(target, state)
    results["smb"] = enumerate_smb(target, state)
    results["anonymous_login"] = check_anonymous_login(target, state)
    results["banners"] = grab_banners(target, state)
    
    print("\n[RECON] Reconnaissance complete")
    print(f"[RECON] {len(state.findings)} findings written to bloodstream")
    print("="*50)
    
    return results