from PyQt6.QtCore import QThread, pyqtSignal
from memnet.forensics.extraction_module import ExtractionModule

class SpecialistWorker(QThread):
    finished = pyqtSignal(str, list)
    error = pyqtSignal(str, str)
    progress = pyqtSignal(int, str)

    def __init__(self, filepath, task_type, pid_map=None):
        super().__init__()
        self.filepath = filepath
        self.task_type = task_type
        self.pid_map = pid_map

    def run(self):
        try:
            extractor = ExtractionModule(self.filepath, progress_callback=self.handle_progress)
            
            if self.task_type == "url":
                results = extractor.extract_urls(self.pid_map)
            elif self.task_type == "browser":
                results = extractor.extract_browser_data(self.pid_map)
            else:
                results = []
                
            self.finished.emit(self.task_type, results)
        except Exception as e:
            error_details = f"{type(e).__name__}: {str(e)}" if str(e) else repr(e)
            self.error.emit(self.task_type, error_details)

    def handle_progress(self, percent, description):
        self.progress.emit(percent, description)

class TorScoutWorker(QThread):
    finished = pyqtSignal(dict)
    error = pyqtSignal(str, str)
    progress = pyqtSignal(int, str)

    def __init__(self, filepath):
        super().__init__()
        self.filepath = filepath

    def run(self):
        from memnet.forensics.vol_engine import VolatilityEngine
        from memnet.forensics.tor_module import TorAnalyzer
        from concurrent.futures import ThreadPoolExecutor
        
        try:
            engine = VolatilityEngine(self.filepath, progress_callback=lambda p, d: self.progress.emit(p, d))
            analyzer = TorAnalyzer(engine)
            
            results = {
                "Execution Traces": [],
                "Network Sessions": [],
                "Browsing History": [],
                "Carved Communications": []
            }

            def scout_network():
                self.progress.emit(10, "Scouting Network Sessions...")
                net_results = engine.run_plugin("windows.netstat.NetStat")
                net_findings = []
                for row in net_results:
                    lport = str(row.get("LocalPort", ""))
                    rport = str(row.get("RemotePort", ""))
                    if lport in ["9150", "9151"] or rport in ["9150", "9151"]:
                        net_findings.append({
                            "name": f"Connection on Port {lport or rport}",
                            "value": f"State: {row.get('State')} | PID: {row.get('PID')}",
                            "source": f"NetStat ({row.get('Proto')})"
                        })
                return net_findings

            def scout_registry():
                self.progress.emit(30, "Scouting Registry for Tor Launchers...")
                reg_findings = []
                try:
                    hives = engine.run_plugin("windows.registry.hivelist.HiveList")
                    for hive in hives:
                        path = str(hive.get("File Path", "")).upper()
                        if "NTUSER.DAT" in path:
                            offset = hive.get("Offset")
                            tor_key = "SOFTWARE\\Mozilla\\Firefox\\Launcher"
                            try:
                                pk_args = {"hive_offset": offset, "key": tor_key}
                                pk_res = engine.run_plugin("windows.registry.printkey.PrintKey", pk_args)
                                for row in pk_res:
                                    reg_findings.append({
                                        "name": "Tor Launcher Trace",
                                        "value": f"Key: {row.get('Key')} | Last Write: {row.get('Last Write Time')}",
                                        "source": f"Registry Hive: {path}"
                                    })
                            except:
                                continue
                except:
                    pass
                return reg_findings

            def scout_files():
                self.progress.emit(60, "Scouting File Artifacts (places.sqlite)...")
                file_findings = []
                files = engine.run_plugin("windows.filescan.FileScan")
                for f in files:
                    fname = str(f.get("Name", "")).lower()
                    if "places.sqlite" in fname or "torbrowser" in fname:
                        file_findings.append({
                            "name": "Potential Browser Database",
                            "value": fname,
                            "source": f"FileScan (Offset: {f.get('Offset')})"
                        })
                return file_findings

            def scout_carving():
                self.progress.emit(80, "Carving .onion links (Multi-Processed)...")
                # This uses FastYaraScanner internally (multiprocessing)
                onions = analyzer.extract_onion_links()
                carve_findings = []
                for o in onions:
                    carve_findings.append({
                        "name": "Deep Web Link (.onion)",
                        "value": o.get("Match"),
                        "source": f"YARA Carving (Offset: {o.get('Offset')})"
                    })
                return carve_findings

            # Execute all scouts in parallel
            with ThreadPoolExecutor(max_workers=4) as executor:
                f_net = executor.submit(scout_network)
                f_reg = executor.submit(scout_registry)
                f_file = executor.submit(scout_files)
                f_carve = executor.submit(scout_carving)

                results["Network Sessions"] = f_net.result()
                results["Execution Traces"] = f_reg.result()
                results["Browsing History"] = f_file.result()
                results["Carved Communications"] = f_carve.result()

            self.progress.emit(100, "Dark Web Investigation Complete (Parallel)")
            self.finished.emit(results)

        except Exception as e:
            self.error.emit("tor", str(e))
