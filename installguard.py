#!/data/data/com.termux/files/usr/bin/env python3
"""
CEX-InstallGuard - Analyze install scripts before execution
Author: CyberEmpireX
Website: https://cyberempirex.com
"""

import sys
import os
import re
import hashlib
import json
from datetime import datetime
from pathlib import Path

# Color codes for terminal
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

class CEXInstallGuard:
    def __init__(self):
        self.version = "v2.0.1"
        self.tool_name = "CEX-InstallGuard"
        self.platform = "Termux (Android)"
        self.license = "MIT"
        self.creator = "CyberEmpireX"
        self.focus = "Practical cybersecurity & research tools"
        self.approach = "Simple, offline-first, ethical"
        self.website = "https://cyberempirex.com"
        self.github = "https://github.com/cyberempirex"
        self.community = "https://t.me/CyberEmpireXChat"
        
        # Dangerous patterns to detect
        self.dangerous_patterns = {
            "HIGH_RISK": [
                r"rm\s+-rf\s+/\s*",  # Delete root
                r"chmod\s+777\s+.*",  # Dangerous permissions
                r">\s*/dev/sda",  # Disk overwrite
                r"dd\s+if=.*of=/dev/",  # Disk cloning
                r"mkfs\.\w+\s+/dev/",  # Format disk
                r":\(\)\{.*:\|:\&.*\};:",  # Fork bomb
                r"curl.*\|\s*bash.*",  # Pipe to bash
                r"wget.*\|\s*bash.*"  # Pipe to bash
            ],
            "MEDIUM_RISK": [
                r"rm\s+-rf\s+~\s*",  # Delete home
                r"chmod\s+777\s+~",  # Home permissions
                r"wget.*\|\s*sh.*",  # Pipe to sh
                r"curl.*\|\s*sh.*",  # Pipe to sh
                r"sudo\s+.*",  # Sudo commands
                r"su\s+-c",  # Switch user
                r"chown\s+-R\s+.*",  # Recursive ownership
                r"echo.*>\s*/etc/"  # Write to system
            ],
            "LOW_RISK": [
                r"apt-get\s+remove.*",  # Remove packages
                r"pkg\s+remove.*",  # Termux remove
                r"pip\s+uninstall.*",  # Python uninstall
                r">>\s*~/.bashrc",  # Modify shell
                r">>\s*~/.zshrc"  # Modify shell
            ]
        }
        
        self.suspicious_keywords = [
            "backdoor", "reverse_shell", "keylogger", "miner",
            "cryptominer", "malware", "trojan", "exploit",
            "payload", "meterpreter", "rat", "botnet"
        ]
    
    def display_banner(self):
        """Display the tool banner"""
        print(f"\n{Colors.CYAN}{Colors.BOLD}")
        print("╔══════════════════════════════════════════════════════════╗")
        print("║                                                          ║")
        print("║        ██████╗███████╗██╗  ██╗    ██╗███╗   ██╗          ║")
        print("║       ██╔════╝██╔════╝╚██╗██╔╝    ██║████╗  ██║          ║")
        print("║       ██║     █████╗   ╚███╔╝     ██║██╔██╗ ██║          ║")
        print("║       ██║     ██╔══╝   ██╔██╗     ██║██║╚██╗██║          ║")
        print("║       ╚██████╗███████╗██╔╝ ██╗    ██║██║ ╚████║          ║")
        print("║        ╚═════╝╚══════╝╚═╝  ╚═╝    ╚═╝╚═╝  ╚═══╝          ║")
        print("║                                                          ║")
        print("║            CEX-InstallGuard v2.0.1                       ║")
        print("║            Analyze install scripts before execution      ║")
        print("║            Created by CyberEmpireX                       ║")
        print("║                                                          ║")
        print("╚══════════════════════════════════════════════════════════╝")
        print(f"{Colors.END}")
        print(f"{Colors.GREEN}{'═'*62}{Colors.END}\n")
    
    def about_section(self):
        """Display the about section"""
        print(f"\n{Colors.CYAN}{Colors.BOLD}")
        print("╔══════════════════════════════════════════════════════════╗")
        print("║                      ABOUT CEX-InstallGuard              ║")
        print("╚══════════════════════════════════════════════════════════╝")
        print(f"{Colors.END}")
        
        print(f"\n{Colors.BOLD}{Colors.WHITE}🔹 Tool Identity{Colors.END}")
        print(f"{Colors.CYAN}{'─'*45}{Colors.END}")
        print(f"{Colors.GREEN}Tool        :{Colors.END} {self.tool_name}")
        print(f"{Colors.GREEN}Version     :{Colors.END} {self.version}")
        print(f"{Colors.GREEN}Purpose     :{Colors.END} Analyze install scripts before execution")
        print(f"{Colors.GREEN}Platform    :{Colors.END} {self.platform}")
        print(f"{Colors.GREEN}License     :{Colors.END} {self.license}")
        
        print(f"\n{Colors.BOLD}{Colors.WHITE}🔹 Creator Identity{Colors.END}")
        print(f"{Colors.CYAN}{'─'*45}{Colors.END}")
        print(f"{Colors.GREEN}Created by  :{Colors.END} {self.creator}")
        print(f"{Colors.GREEN}Focus       :{Colors.END} {self.focus}")
        print(f"{Colors.GREEN}Approach    :{Colors.END} {self.approach}")
        
        print(f"\n{Colors.BOLD}{Colors.WHITE}🔹 Project Links{Colors.END}")
        print(f"{Colors.CYAN}{'─'*45}{Colors.END}")
        print(f"{Colors.GREEN}Website     :{Colors.END} {self.website}")
        print(f"{Colors.GREEN}GitHub      :{Colors.END} {self.github}")
        print(f"{Colors.GREEN}Community   :{Colors.END} {self.community}")
        
        print(f"\n{Colors.BOLD}{Colors.WHITE}🔹 Ethics Notice{Colors.END}")
        print(f"{Colors.CYAN}{'─'*45}{Colors.END}")
        print(f"{Colors.YELLOW}This tool is for educational and defensive use only.")
        print(f"Use only on scripts and systems you own or trust.")
        print(f"The author is not responsible for misuse.{Colors.END}")
        
        print(f"\n{Colors.BOLD}{Colors.WHITE}🔹 Build Info{Colors.END}")
        print(f"{Colors.CYAN}{'─'*45}{Colors.END}")
        print(f"{Colors.GREEN}Built With  :{Colors.END} Python 3")
        print(f"{Colors.GREEN}Framework   :{Colors.END} CEX Builder")
        print(f"{Colors.GREEN}Generated   :{Colors.END} CEX Professional Toolkit")
        
        print(f"\n{Colors.MAGENTA}Press Enter to return to main menu...{Colors.END}")
        input()
    
    def analyze_script(self):
        """Analyze a script file"""
        print(f"\n{Colors.BLUE}{Colors.BOLD}")
        print("╔══════════════════════════════════════════════════════════╗")
        print("║                    SCRIPT ANALYSIS                       ║")
        print("╚══════════════════════════════════════════════════════════╝")
        print(f"{Colors.END}")
        
        # Get script path
        script_path = input(f"\n{Colors.CYAN}Enter script path: {Colors.END}").strip()
        
        if not os.path.exists(script_path):
            print(f"{Colors.RED}Error: File not found!{Colors.END}")
            return
        
        print(f"\n{Colors.GREEN}[+] Analyzing: {script_path}{Colors.END}")
        print(f"{Colors.WHITE}{'─'*60}{Colors.END}")
        
        try:
            with open(script_path, 'r', encoding='utf-8') as f:
                content = f.read()
                lines = content.split('\n')
        except Exception as e:
            print(f"{Colors.RED}Error reading file: {e}{Colors.END}")
            return
        
        # File information
        file_hash = hashlib.sha256(content.encode()).hexdigest()[:16]
        file_size = os.path.getsize(script_path)
        line_count = len(lines)
        
        print(f"\n{Colors.BOLD}{Colors.WHITE}📄 File Information{Colors.END}")
        print(f"{Colors.CYAN}{'─'*45}{Colors.END}")
        print(f"{Colors.GREEN}Path    :{Colors.END} {script_path}")
        print(f"{Colors.GREEN}Size    :{Colors.END} {file_size} bytes")
        print(f"{Colors.GREEN}Lines   :{Colors.END} {line_count}")
        print(f"{Colors.GREEN}Hash    :{Colors.END} {file_hash}")
        
        # Analysis results
        findings = {
            "HIGH_RISK": [],
            "MEDIUM_RISK": [],
            "LOW_RISK": [],
            "SUSPICIOUS_KEYWORDS": []
        }
        
        # Check each line
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            # Check dangerous patterns
            for risk_level, patterns in self.dangerous_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        findings[risk_level].append({
                            "line": line_num,
                            "content": line[:80] + ("..." if len(line) > 80 else "")
                        })
                        break
            
            # Check suspicious keywords
            for keyword in self.suspicious_keywords:
                if keyword in line.lower():
                    findings["SUSPICIOUS_KEYWORDS"].append({
                        "line": line_num,
                        "keyword": keyword,
                        "content": line[:60]
                    })
        
        # Display findings
        self.display_findings(findings)
    
    def display_findings(self, findings):
        """Display analysis findings with colors"""
        high_count = len(findings["HIGH_RISK"])
        medium_count = len(findings["MEDIUM_RISK"])
        low_count = len(findings["LOW_RISK"])
        keyword_count = len(findings["SUSPICIOUS_KEYWORDS"])
        
        print(f"\n{Colors.BOLD}{Colors.WHITE}📊 Risk Assessment{Colors.END}")
        print(f"{Colors.CYAN}{'─'*45}{Colors.END}")
        
        # Risk levels
        if high_count > 0:
            print(f"{Colors.RED}High Risk    : {high_count} patterns ⚠️⚠️⚠️{Colors.END}")
        else:
            print(f"{Colors.GREEN}High Risk    : {high_count} patterns ✅{Colors.END}")
            
        if medium_count > 0:
            print(f"{Colors.YELLOW}Medium Risk  : {medium_count} patterns ⚠️⚠️{Colors.END}")
        else:
            print(f"{Colors.GREEN}Medium Risk  : {medium_count} patterns ✅{Colors.END}")
            
        if low_count > 0:
            print(f"{Colors.YELLOW}Low Risk     : {low_count} patterns ⚠️{Colors.END}")
        else:
            print(f"{Colors.GREEN}Low Risk     : {low_count} patterns ✅{Colors.END}")
        
        if keyword_count > 0:
            print(f"{Colors.MAGENTA}Suspicious   : {keyword_count} keywords 🔍{Colors.END}")
        else:
            print(f"{Colors.GREEN}Suspicious   : {keyword_count} keywords ✅{Colors.END}")
        
        # Overall verdict
        total_risks = high_count + medium_count + low_count
        
        print(f"\n{Colors.BOLD}{Colors.WHITE}🔍 Overall Verdict{Colors.END}")
        print(f"{Colors.CYAN}{'─'*45}{Colors.END}")
        
        if high_count > 0:
            print(f"{Colors.RED}{Colors.BOLD}❌ DANGEROUS: DO NOT EXECUTE!{Colors.END}")
            print(f"{Colors.RED}This script contains high-risk commands.{Colors.END}")
        elif medium_count > 0:
            print(f"{Colors.YELLOW}{Colors.BOLD}⚠️  CAUTION: Review carefully{Colors.END}")
            print(f"{Colors.YELLOW}Contains medium-risk commands.{Colors.END}")
        elif low_count > 0 or keyword_count > 0:
            print(f"{Colors.YELLOW}{Colors.BOLD}⚠️  WARNING: Some risks detected{Colors.END}")
            print(f"{Colors.YELLOW}Contains low-risk patterns.{Colors.END}")
        else:
            print(f"{Colors.GREEN}{Colors.BOLD}✅ CLEAN: Seems safe{Colors.END}")
            print(f"{Colors.GREEN}No dangerous patterns detected.{Colors.END}")
        
        # Show sample findings
        if total_risks > 0:
            print(f"\n{Colors.BOLD}{Colors.WHITE}📝 Sample Findings{Colors.END}")
            print(f"{Colors.CYAN}{'─'*45}{Colors.END}")
            
            # Show high risk findings
            if high_count > 0:
                print(f"\n{Colors.RED}High Risk Examples:{Colors.END}")
                for finding in findings["HIGH_RISK"][:3]:
                    print(f"  Line {finding['line']}: {finding['content']}")
            
            # Show suspicious keywords
            if keyword_count > 0:
                print(f"\n{Colors.MAGENTA}Suspicious Keywords Found:{Colors.END}")
                seen_keywords = set()
                for finding in findings["SUSPICIOUS_KEYWORDS"]:
                    if finding['keyword'] not in seen_keywords:
                        print(f"  '{finding['keyword']}' found in script")
                        seen_keywords.add(finding['keyword'])
        
        print(f"\n{Colors.MAGENTA}Press Enter to continue...{Colors.END}")
        input()
    
    def quick_scan(self):
        """Quick scan of common install commands"""
        print(f"\n{Colors.BLUE}{Colors.BOLD}")
        print("╔══════════════════════════════════════════════════════════╗")
        print("║                     QUICK COMMAND SCAN                   ║")
        print("╚══════════════════════════════════════════════════════════╝")
        print(f"{Colors.END}")
        
        print(f"\n{Colors.YELLOW}Enter commands to analyze (type 'DONE' on new line to finish):{Colors.END}")
        print(f"{Colors.CYAN}{'─'*60}{Colors.END}")
        
        commands = []
        while True:
            cmd = input(f"{Colors.WHITE}> {Colors.END}").strip()
            if cmd.upper() == "DONE":
                break
            if cmd:
                commands.append(cmd)
        
        if not commands:
            print(f"{Colors.YELLOW}No commands entered.{Colors.END}")
            return
        
        findings = {
            "HIGH_RISK": [],
            "MEDIUM_RISK": [],
            "LOW_RISK": [],
            "SUSPICIOUS_KEYWORDS": []
        }
        
        # Analyze each command
        for idx, cmd in enumerate(commands, 1):
            for risk_level, patterns in self.dangerous_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, cmd, re.IGNORECASE):
                        findings[risk_level].append({
                            "line": idx,
                            "content": cmd[:80] + ("..." if len(cmd) > 80 else "")
                        })
                        break
            
            # Check keywords
            for keyword in self.suspicious_keywords:
                if keyword in cmd.lower():
                    findings["SUSPICIOUS_KEYWORDS"].append({
                        "line": idx,
                        "keyword": keyword,
                        "content": cmd[:60]
                    })
        
        self.display_findings(findings)
    
    def main_menu(self):
        """Display main menu"""
        while True:
            self.display_banner()
            
            print(f"{Colors.BOLD}{Colors.WHITE}MAIN MENU{Colors.END}")
            print(f"{Colors.CYAN}{'═'*62}{Colors.END}")
            print(f"{Colors.GREEN}1.{Colors.END} Analyze Script File")
            print(f"{Colors.GREEN}2.{Colors.END} Quick Command Scan")
            print(f"{Colors.GREEN}3.{Colors.END} About CEX-InstallGuard")
            print(f"{Colors.GREEN}4.{Colors.END} Exit")
            print(f"{Colors.CYAN}{'═'*62}{Colors.END}")
            
            choice = input(f"\n{Colors.YELLOW}Select option (1-4): {Colors.END}").strip()
            
            if choice == "1":
                self.analyze_script()
            elif choice == "2":
                self.quick_scan()
            elif choice == "3":
                self.about_section()
            elif choice == "4":
                print(f"\n{Colors.GREEN}Thank you for using CEX-InstallGuard!{Colors.END}")
                print(f"{Colors.CYAN}Stay secure! 🔒{Colors.END}\n")
                break
            else:
                print(f"{Colors.RED}Invalid option! Please try again.{Colors.END}")

def main():
    """Main function"""
    # Check if running in Termux
    if not os.path.exists('/data/data/com.termux/files/usr'):
        print(f"{Colors.RED}Warning: This tool is optimized for Termux.{Colors.END}")
    
    # Create and run the tool
    tool = CEXInstallGuard()
    tool.main_menu()

if __name__ == "__main__":
    main()
