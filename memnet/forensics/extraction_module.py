import logging
import tempfile
import os
from .fast_scanner import FastYaraScanner

logger = logging.getLogger(__name__)

class ExtractionModule:
    """
    Specialist module for deep memory artifact extraction.
    Uses high-performance native YARA scanning.
    """
    
    URL_YARA = "rule WebURL {\n" \
               "    strings:\n" \
               "        $s1 = /https?:\\/\\/[a-z0-9][a-z0-9.\\-]+[a-z0-9]\\.[a-z]{2,5}[^\\s\"'<>()]*/ nocase ascii wide\n" \
               "    condition:\n" \
               "        $s1\n" \
               "}"

    BROWSER_YARA = "rule BrowserHistory {\n" \
                   "    meta:\n" \
                   "        desc = \"Detects browser markers and sqlite database signatures\"\n" \
                   "    strings:\n" \
                   "        $sqlite = \"SQLite format 3\" ascii wide\n" \
                   "        $chrome_pref = \"Software\\\\Google\\\\Chrome\" ascii wide nocase\n" \
                   "        $firefox_pref = \"Software\\\\Mozilla\\\\Firefox\" ascii wide nocase\n" \
                   "        $history_url = /google\\.com\\/search\\?q=[^\\s]*/ ascii wide nocase\n" \
                   "        $cookie = \"Set-Cookie:\" ascii wide nocase\n" \
                   "        $chrome_v8 = \"v8/\" ascii wide nocase\n" \
                   "    condition:\n" \
                   "        any of them\n" \
                   "}"

    DARK_WEB_YARA = "rule OnionAddress {\n" \
                    "    meta:\n" \
                    "        desc = \"Detects standard and v3 Tor .onion addresses\"\n" \
                    "    strings:\n" \
                    "        $onion = /[a-z2-7]{16,56}\\.onion/ nocase ascii wide\n" \
                    "    condition:\n" \
                    "        $onion\n" \
                    "}\n" \
                    "rule EmailJSON {\n" \
                    "    meta:\n" \
                    "        desc = \"Detects JSON email structures\"\n" \
                    "    strings:\n" \
                    "        $s1 = \"\\\"subject\\\":\" ascii wide nocase\n" \
                    "        $s2 = \"\\\"body\\\":\" ascii wide nocase\n" \
                    "        $s3 = \"\\\"to\\\":\" ascii wide nocase\n" \
                    "        $s4 = \"\\\"from\\\":\" ascii wide nocase\n" \
                    "    condition:\n" \
                    "        any of them\n" \
                    "}"

    def __init__(self, filepath, progress_callback=None):
        self.filepath = filepath
        self.progress_callback = progress_callback

    def _run_yara(self, rule_str, pid_map=None):
        try:
            scanner = FastYaraScanner(self.filepath, rule_str, progress_callback=self.progress_callback)
            results = scanner.scan()
            
            if pid_map:
                for res in results:
                    phys_offset = int(res["Offset"], 16)
                    # Stitching: Find which process 'owns' this part of the dump
                    # Note: For physical dumps, this is a heuristic match based on VAD density
                    # or proximity if exact mapping isn't available.
                    # Simplified: We'll add a 'PID' key to the finding.
                    res["PID"] = "N/A"
                    for vad in pid_map:
                        if vad["Start"] <= phys_offset <= vad["End"]:
                            res["PID"] = str(vad["PID"])
                            break
            return results
        except Exception as e:
            error_msg = f"FAST SCANNER ERROR: {str(e)}"
            logger.error(error_msg)
            raise RuntimeError(error_msg)

    def extract_urls(self, pid_map=None):
        logger.info("Extracting URLs via FastScanner...")
        return self._run_yara(self.URL_YARA, pid_map)

    def extract_browser_data(self, pid_map=None):
        logger.info("Extracting Browser artifacts via FastScanner...")
        return self._run_yara(self.BROWSER_YARA, pid_map)

    def extract_dark_web_data(self, pid_map=None):
        logger.info("Extracting Dark Web artifacts via FastScanner...")
        return self._run_yara(self.DARK_WEB_YARA, pid_map)
