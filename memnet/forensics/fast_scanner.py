import yara
import os
import multiprocessing
from concurrent.futures import ProcessPoolExecutor
import logging
import re

logger = logging.getLogger(__name__)

def _scan_chunk_static(filepath, rules_str, start, end):
    """Stand-alone function for picklable multi-processing."""
    try:
        local_rules = yara.compile(source=rules_str)
        findings = []
        with open(filepath, 'rb') as f:
            f.seek(start)
            data = f.read(end - start)
            matches = local_rules.match(data=data)
            
            for match in matches:
                for instance in match.strings:
                    try:
                        # Defensive extraction
                        if hasattr(instance, 'instances'):
                            # Some versions have a list of instances per string
                            first = instance.instances[0]
                            offset = start + first.offset
                            value = first.matched_data
                        elif hasattr(instance, 'offset'):
                            offset = start + instance.offset
                            value = instance.data
                        else:
                            offset = start + instance[0]
                            value = instance[2]
                            
                        # Try to detect UTF-16 (Common in Windows memory)
                        # Pattern: Every other byte is null
                        is_wide = False
                        if len(value) >= 4:
                            # Check for common UTF-16LE pattern: [char, 0, char, 0]
                            nulls = value[1::2]
                            if len(nulls) > 0 and all(b == 0 for b in nulls):
                                is_wide = True
                        
                        if is_wide:
                            decoded = value.decode('utf-16le', errors='ignore').strip()
                        else:
                            decoded = value.decode('utf-8', errors='ignore').strip()
                        
                        # Post-processing: Remove all internal nulls and non-printable junk
                        # This handles cases where UTF-8 ignore left spaces or weird chars
                        decoded = "".join(c for c in decoded if c.isprintable()).strip()
                        
                        # Break concatenated URLs (common in raw memory)
                        # e.g. "http://A.comhttp://B.com" -> "http://A.com"
                        if "http" in decoded[4:]:
                            decoded = decoded[:decoded.find("http", 4)].strip()

                        # Final polish: Remove characters that definitely shouldn't be in a URL if they appear after symbols
                        decoded = re.sub(r'[\u0000-\u001F\u007F-\u009F].*$', '', decoded)
                        
                        # Minimum length for utility
                        if decoded and len(decoded) > 10:
                            findings.append({
                                "Offset": hex(offset),
                                "Rule": match.rule,
                                "Match": decoded
                            })
                    except Exception:
                        pass
        return findings
    except Exception as e:
        logger.error(f"Worker fatal error in range {start}-{end}: {e}")
        return []

class FastYaraScanner:
    """
    A high-speed, multi-processed YARA scanner for raw memory dumps.
    Avoids Volatility overhead for simple artifact harvesting.
    """
    
    # Common Forensic Noise Filter (strips out non-actionable metadata)
    BLACKLIST = [
        "w3.org", "schemas.microsoft.com", "xmlns", "purl.org", 
        "apple.com/dtds", "openxmlformats.org", "adobe.com/xap",
        "ns.adobe.com", "google.com/schemas", "xmldsig", "tempuri.org",
        "ogp.me", "microformats.org", "w3c", "iec.ch", "mozilla.org/mpl",
        "verisign.com", "globalsign.com"
    ]

    def __init__(self, filepath, rules_str, progress_callback=None):
        self.filepath = filepath
        self.rules_str = rules_str
        self.progress_callback = progress_callback
        # Verify compilation here before spawning processes
        try:
            yara.compile(source=rules_str)
        except Exception as e:
            logger.error(f"YARA Compile Error: {e}")
            raise

    def scan(self):
        """Perform a chunked parallel scan of the memory dump."""
        file_size = os.path.getsize(self.filepath)
        chunk_size = 128 * 1024 * 1024 
        overlap = 1024 
        
        chunks = []
        for start in range(0, file_size, chunk_size):
            end = min(start + chunk_size + overlap, file_size)
            chunks.append((start, end))

        results = []
        cpu_count = multiprocessing.cpu_count()
        logger.info(f"Starting parallel scan with {cpu_count} cores")
        
        with ProcessPoolExecutor(max_workers=cpu_count) as executor:
            # Pass static function and picklable arguments
            futures = [executor.submit(_scan_chunk_static, self.filepath, self.rules_str, start, end) for start, end in chunks]
            
            for i, future in enumerate(futures):
                try:
                    chunk_results = future.result()
                    results.extend(chunk_results)
                    if self.progress_callback:
                        prog = int(((i + 1) / len(futures)) * 100)
                        self.progress_callback(prog, f"Scanning Memory Chunk {i+1}/{len(futures)}...")
                except Exception as e:
                    logger.error(f"Chunk scan failed: {e}")

        return self._filter_results(results)

    def _filter_results(self, results):
        """Remove duplicates and low-relevance noise."""
        unique_findings = {}
        filtered = []
        
        for res in results:
            match_str = res["Match"]
            
            if len(match_str) < 10 or len(match_str) > 500:
                continue
                
            if any(noise in match_str.lower() for noise in self.BLACKLIST):
                continue
                
            sig = match_str[:120]
            if sig not in unique_findings:
                unique_findings[sig] = True
                filtered.append(res)
                
        filtered.sort(key=lambda x: int(x["Offset"], 16))
        return filtered
