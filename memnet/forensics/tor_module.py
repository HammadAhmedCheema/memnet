import re
import os
import logging
from .vol_engine import VolatilityEngine

logger = logging.getLogger(__name__)

class TorAnalyzer:
    """
    Advanced Specialist Module for Tor Forensics.
    Uses pslist to identify tor execution and yarascan to locate .onion strings.
    """
    
    ONION_YARA_RULE = "rule OnionURL {\n" \
                      "    meta:\n" \
                      "        description = \"Detects .onion URLs in memory\"\n" \
                      "    strings:\n" \
                      "        $v2 = /[a-z2-7]{16}\\.onion/ nocase\n" \
                      "        $v3 = /[a-z2-7]{56}\\.onion/ nocase\n" \
                      "    condition:\n" \
                      "        $v2 or $v3\n" \
                      "}"
    def __init__(self, engine: VolatilityEngine):
        self.engine = engine

    def find_tor_processes(self):
        """
        Scans process list for 'tor.exe' or 'firefox' running loosely typical tor paths.
        """
        logger.info("Scanning for Tor-related processes...")
        try:
            results = self.engine.run_plugin("windows.pslist.PsList")
        except Exception as e:
            logger.error(f"Failed to run pslist: {e}")
            return []

        suspects = []
        for row in results:
            img = str(row.get("ImageFileName", "")).lower()
            if "tor" in img or "vidalia" in img:
                suspects.append(row)
        return suspects

    def extract_onion_links(self):
        """
        Runs a Yara scan against the memory dump to find instances of .onion URLs.
        Depending on image size, this can take a long time.
        """
        logger.info("Scanning memory for .onion patterns using Yara...")
        try:
            import tempfile
            from urllib.request import pathname2url
            
            with tempfile.NamedTemporaryFile(delete=False, suffix=".yara", mode="w") as f:
                f.write(self.ONION_YARA_RULE)
                temp_yara_path = f.name
                
            yara_args = {
                "yara_file": "file://" + pathname2url(temp_yara_path)
            }
            results = self.engine.run_plugin("yarascan.YaraScan", yara_args)
            
            # Cleanup temp file
            try:
                os.remove(temp_yara_path)
            except Exception:
                pass
            
            # The YaraScan returns columns: Offset, Rule, Component, Value
            # Values are hex encoded or raw strings. So we decode if needed.
            onion_findings = []
            for row in results:
                value = row.get("Value", "")
                if value:
                    try:
                        # decode from hex if it's hex format
                        if all(c in "0123456789abcdefABCDEF" for c in value) and len(value) % 2 == 0:
                            decoded = bytes.fromhex(value).decode('ascii', errors='ignore')
                        else:
                            decoded = str(value)
                        
                        onion_findings.append({
                            "Offset": row.get("Offset"),
                            "Rule": row.get("Rule"),
                            "Match": decoded.strip()
                        })
                    except Exception:
                        pass
                        
            return onion_findings
        except Exception as e:
            logger.error(f"Failed to run yarascan: {e}")
            return []
