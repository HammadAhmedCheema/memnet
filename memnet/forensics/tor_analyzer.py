import json

class TorAnalyzer:
    def __init__(self, session_data):
        self.session_data = session_data

    def analyze(self):
        """
        Analyzes scan results for Tor indicators from in-memory session data.
        Returns a dict with triage status and details.
        """
        is_tor_positive = False
        evidence = []

        for mod_name, results in self.session_data.items():
            # Process List Check
            if "pslist" in mod_name.lower():
                for process in results:
                    img_name = str(process.get("ImageFileName", "")).lower()
                    if img_name == "tor.exe":
                        is_tor_positive = True
                        evidence.append(f"Found executing Tor process (PID: {process.get('PID')})")

            # Network Check
            if "netstat" in mod_name.lower():
                for net in results:
                    local_port = str(net.get("LocalPort", ""))
                    if local_port in ["9150", "9151"]:
                        is_tor_positive = True
                        evidence.append(f"Found Tor SOCKS proxy port connection ({local_port}) PID: {net.get('PID')}")

        status = "Tor-Positive" if is_tor_positive else "Negative"
        return {"status": status, "evidence": evidence}
