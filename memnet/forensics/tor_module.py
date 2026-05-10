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

    def extract_onion_links(self, progress_callback=None):
        """
        Runs a high-performance multi-processed Yara scan against the memory dump.
        Replaces the slow Volatility yarascan plugin.
        """
        logger.info("Performing high-speed parallel scan for .onion patterns...")
        from .extraction_module import ExtractionModule
        
        try:
            # Use the dedicated extraction module which leverages all CPU cores
            extractor = ExtractionModule(self.engine.filepath, progress_callback=progress_callback)
            results = extractor.extract_dark_web_data()
            
            # Format results to match the expected structure
            # ExtractionModule returns list of: {"Offset": "0x...", "Rule": "...", "Match": "..."}
            return results
        except Exception as e:
            logger.error(f"Fast .onion extraction failed: {e}")
            return []
