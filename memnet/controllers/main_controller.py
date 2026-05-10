from PyQt6.QtWidgets import QFileDialog, QMessageBox, QInputDialog, QLineEdit
from PyQt6.QtCore import QTimer
import os
import json
from memnet.views.main_window import MainWindow
from memnet.controllers.file_import_worker import FileImportWorker
from memnet.controllers.vol_scan_worker import VolScanWorker
from memnet.controllers.ai_worker import AIWorker
from memnet.controllers.specialist_worker import SpecialistWorker
from memnet.controllers.vad_worker import VadCacheWorker
from memnet.forensics.tor_analyzer import TorAnalyzer
from memnet.constants.plugin_map import PLUGIN_MAP
from memnet.models.database import init_db, insert_scan_result, cleanup_session_db, get_connection, get_all_scan_results

class MainController:
    def __init__(self):
        self.view = MainWindow()
        self.worker = None
        
        # Connect close cleanup
        self.view.closing.connect(cleanup_session_db)
        
        # Connect signals
        self.view.dashboard_view.import_btn.clicked.connect(self.handle_import)
        
        for view in [self.view.process_view, self.view.network_view, self.view.threat_view, 
                     self.view.system_view]:
            view.execute_plugin.connect(self.handle_plugin_execute)
            view.add_to_graph.connect(self.handle_add_graph)
            
        self.view.extraction_view.extract_url_btn.clicked.connect(lambda: self.run_specialist_scan("url"))
        self.view.extraction_view.extract_browser_btn.clicked.connect(lambda: self.run_specialist_scan("browser"))
        self.view.extraction_view.add_to_graph.connect(self.handle_add_graph)
        
        self.view.ai_analyst_view.generate_btn.clicked.connect(self.generate_ai_report)
        self.view.ai_analyst_view.export_btn.clicked.connect(self.export_report)
        
        self.view.graph_view.node_click_callback = self.handle_node_click
        
        # Tor Evidence Signal
        self.view.tor_view.investigate_clicked.connect(self.handle_tor_investigation)
        
        self.ai_client = None
        self.chat_session = None
        
        self.cached_vad_map = None
        self.active_scanners = []
        self.scan_queue = [] # List of (type, args)
        self.session_data = {} # In-memory storage for current session
        self.current_filepath = None
        self.batch_mode = False
        
    def show(self):
        self.view.show()
        
    def handle_import(self):
        filepath, _ = QFileDialog.getOpenFileName(self.view, "Select Memory Dump", "", "Memory Dumps (*.raw *.mem *.vmem *.bin *.E01);;All Files(*)")
        if not filepath:
            return
            
        # UI Feedback
        self.view.dashboard_view.import_btn.setEnabled(False)
        self.view.dashboard_view.progress_bar.setValue(0)
        self.view.dashboard_view.progress_bar.show()
        self.view.dashboard_view.file_path_display.setText(filepath)
        
        self.worker = FileImportWorker(filepath)
        self.worker.progress.connect(self.handle_progress_update)
        self.worker.finished.connect(lambda md5, sha256, path: self.import_finished(path, md5, sha256))
        self.worker.error.connect(self.import_error)
        self.worker.start()
        
    def import_finished(self, filepath, md5_hash, sha256_hash):
        self.view.dashboard_view.import_btn.setEnabled(True)
        self.view.dashboard_view.progress_bar.hide()
        
        # Initialize Fresh Session DB for each import
        init_db()
        
        # Fresh Session
        self.session_data = {}
        self.current_filepath = filepath
        
        self.view.dashboard_view.update_hashes(md5_hash, sha256_hash)
        QMessageBox.information(self.view, "Load Complete", "Evidence image verified. Automated analysis starting now.")
        
        # Trigger Automated Pipeline
        self.execute_full_analysis()

    def execute_full_analysis(self):
        """
        High-Performance Mode: Launches all modules simultaneously to utilize full CPU/RAM.
        """
        if not self.current_filepath:
            return

        # Visual cues on dashboard
        dash = self.view.dashboard_view
        dash.total_processes.value_widget.setText("ANALYZING...")
        dash.network_conns.value_widget.setText("ANALYZING...")
        dash.url_count.value_widget.setText("ANALYZING...")
        dash.browser_count.value_widget.setText("ANALYZING...")

        # Disable tabs during analysis
        self.toggle_tabs(False)

        # 1. Parallel Volatility Scans
        # We stagger these slightly to prevent race conditions in Volatility's symbol caching
        self.batch_mode = True
        self.run_vol_scan_internal("windows.pslist.PsList", self.view.process_view)
        QTimer.singleShot(300, lambda: self.run_vol_scan_internal("windows.netstat.NetStat", self.view.network_view))

        # 2. Parallel Specialist Scans (YARA/Bulk Extraction)
        QTimer.singleShot(600, lambda: self.run_specialist_scan_internal("url"))
        QTimer.singleShot(900, lambda: self.run_specialist_scan_internal("browser"))
        
        # Release batch lock after all have been triggered
        QTimer.singleShot(1200, self._finish_batch_trigger)

        # Note: We removed the sequential scan_queue. 
        # The toggle_tabs(True) will be handled once all active_scanners are empty.
        # We need a small check in plugin_finished/extraction_finished to see if we're done.


    def toggle_tabs(self, enabled: bool):
        """Enable or disable all forensic tabs except the Dashboard."""
        # Index 0 is Dashboard, we keep it enabled
        for i in range(1, self.view.tabs.count()):
            self.view.tabs.setTabEnabled(i, enabled)

    def process_scan_queue(self):
        """Takes the next scan from the queue or finishes the session if all parallel tasks are done."""
        if not self.scan_queue:
            # Check if we still have background workers running or if we are still launching them
            if self.batch_mode or len(self.active_scanners) > 0:
                return # Still working...

            # Re-enable tabs
            self.toggle_tabs(True)
            
            # Run Tor Triage Analysis (Final Post-Processing)
            if self.current_filepath:
                from memnet.forensics.tor_analyzer import TorAnalyzer
                analyzer = TorAnalyzer(self.session_data)
                triage_res = analyzer.analyze()
                status = triage_res.get("status", "Negative")
                self.view.dashboard_view.dark_web_indicator.value_widget.setText(status)
                if status == "Tor-Positive":
                    self.view.dashboard_view.dark_web_indicator.value_widget.setStyleSheet("color: #DC2626; font-weight: bold;")
            return

        scan_type, *args = self.scan_queue.pop(0)
        
        if scan_type == "vol":
            plugin_name, view_widget = args
            self.run_vol_scan_internal(plugin_name, view_widget)
        elif scan_type == "spec":
            task_type = args[0]
            self.run_specialist_scan_internal(task_type)
            
    def _finish_batch_trigger(self):
        self.batch_mode = False
        self.process_scan_queue()

    def handle_plugin_execute(self, plugin_alias, params):
        if not self.current_filepath:
            QMessageBox.warning(self.view, "No Data", "Please import a memory dump first.")
            return

        plugin_name = PLUGIN_MAP.get(plugin_alias)
        if not plugin_name:
            return

        # Check In-Memory Cache
        cached_data = self.session_data.get(plugin_name)
        view_widget = self.get_active_tab_widget()
        
        if cached_data:
            view_widget.update_results(cached_data)
            return

        # Execute
        view_widget.run_btn.setEnabled(False)
        view_widget.status_label.setText(f"// EXECUTING: {plugin_name}...")
        
        worker = VolScanWorker(self.current_filepath, plugin_name, params)
        worker.progress.connect(self.handle_progress_update)
        worker.finished.connect(lambda p_name, res, p_args: self.plugin_finished(worker, p_name, res, p_args, view_widget))
        worker.error.connect(lambda p_name, err: self.plugin_error(worker, p_name, err, view_widget))
        worker.start()
        self.active_scanners.append(worker)

    def get_active_tab_widget(self):
        current_tab = self.view.tabs.currentWidget()
        return current_tab

    def plugin_finished(self, worker, plugin_name, results, params, view_widget):
        try:
            if worker in self.active_scanners:
                self.active_scanners.remove(worker)
            
            if view_widget and hasattr(view_widget, 'run_btn'):
                view_widget.run_btn.setEnabled(True)
            
            if view_widget and hasattr(view_widget, 'update_results'):
                view_widget.update_results(results)
            
            # Store in session for AI/Re-use
            self.session_data[plugin_name] = results
            insert_scan_result(plugin_name, json.dumps(results))

            # Update Dashboard Stats
            dash = self.view.dashboard_view
            if "pslist" in plugin_name.lower():
                dash.total_processes.value_widget.setText(str(len(results)))
            elif "netstat" in plugin_name.lower():
                dash.network_conns.value_widget.setText(str(len(results)))
            
            # Update AI Artifact Counter
            self.update_ai_artifact_count()
                
        except Exception as e:
            self.handle_critical_error(f"Post-Plugin processing failed: {plugin_name}", str(e))

    def plugin_error(self, worker, plugin_name, error_msg, view_widget):
        if worker in self.active_scanners:
            self.active_scanners.remove(worker)
        
        if view_widget and hasattr(view_widget, 'run_btn'):
            view_widget.run_btn.setEnabled(True)
        if view_widget and hasattr(view_widget, 'status_label'):
            view_widget.status_label.setText(f"// ERROR: {error_msg[:50]}...")
            
        # Reduce noise for common plugin requirements failures or during batch mode
        is_noisy = any(x in error_msg for x in ["UnsatisfiedException", "Symbol file not found", "No suitable configuration"])
        
        if self.batch_mode or is_noisy:
             print(f"[PLUGIN SKIPPED] {plugin_name}: {error_msg}")
        else:
            self.handle_critical_error(f"Plugin Failed: {plugin_name}", error_msg)
            
        self.process_scan_queue()

    def handle_critical_error(self, title, message):
        """Unified error reporting for the forensic pipeline."""
        print(f"[CRITICAL ERROR] {title}: {message}")
        # Ensure we always notify the user visually
        QMessageBox.critical(self.view, title, f"An automated component failed:\n\n{message}")

    def run_vol_scan_internal(self, plugin_name, view_widget):
        view_widget.status_label.setText(f"// AUTOMATED SCAN: {plugin_name}...")
        worker = VolScanWorker(self.current_filepath, plugin_name)
        self.active_scanners.append(worker) # Add before starting
        worker.progress.connect(self.handle_progress_update)
        worker.finished.connect(lambda p_name, res, p_args: self.plugin_finished(worker, p_name, res, p_args, view_widget))
        worker.error.connect(lambda p_name, err: self.plugin_error(worker, p_name, err, view_widget))
        worker.finished.connect(lambda: self.process_scan_queue())
        worker.start()

    def run_specialist_scan_internal(self, task_type):
        status_widget = self.view.extraction_view.url_status if task_type == "url" else self.view.extraction_view.browser_status
        status_widget.setText("Requesting VAD Context...")
        
        # Ensure VAD map is ready for stitching
        if not self.cached_vad_map:
            status_widget.setText("Stitching Memory Context (VAD - Background)...")
            worker = VadCacheWorker(self.current_filepath)
            self.active_scanners.append(worker)
            worker.progress.connect(self.handle_progress_update)
            worker.finished.connect(lambda vmap: self._on_vad_cache_completed(worker, vmap, task_type, status_widget))
            worker.error.connect(lambda err: self._on_vad_cache_error(worker, err, status_widget, task_type))
            worker.start()
        else:
            self._start_specialist_worker(task_type, status_widget)

    def _on_vad_cache_completed(self, worker, vad_map, task_type, status_widget):
        if worker in self.active_scanners:
            self.active_scanners.remove(worker)
        self.cached_vad_map = vad_map
        self._start_specialist_worker(task_type, status_widget)

    def _on_vad_cache_error(self, worker, err_msg, status_widget, task_type):
        if worker in self.active_scanners:
            self.active_scanners.remove(worker)
        print(f"VAD Cache Failed: {err_msg}")
        self.cached_vad_map = []
        self._start_specialist_worker(task_type, status_widget)

    def _start_specialist_worker(self, task_type, status_widget):
        status_widget.setText("Scanning memory regions...")
        worker = SpecialistWorker(self.current_filepath, task_type, self.cached_vad_map)
        self.active_scanners.append(worker)
        worker.progress.connect(self.handle_progress_update)
        worker.finished.connect(lambda t, res: self.extraction_finished(worker, t, res))
        worker.error.connect(lambda t, err: self.extraction_error(worker, t, err))
        worker.start()


        # Continue Queue
        self.process_scan_queue()


    def extraction_finished(self, worker, task_type, results):
        try:
            if worker in self.active_scanners:
                self.active_scanners.remove(worker)
                
            view = self.view.extraction_view
            dash = self.view.dashboard_view
            # Sync to Session DB
            insert_scan_result(f"specialist_{task_type}", json.dumps(results))
            
            # Update Dashboard
            if task_type == "url":
                view.url_status.setText(f"Finished: {len(results)} matches.")
                view.populate_table(view.url_table, results)
                dash.url_count.value_widget.setText(str(len(results)))
            else:
                view.browser_status.setText(f"Finished: {len(results)} items.")
                view.populate_table(view.browser_table, results)
                dash.browser_count.value_widget.setText(str(len(results)))

            # Update AI Artifact Counter
            self.update_ai_artifact_count()
        except Exception as e:
            self.handle_critical_error(f"Specialist extraction post-processing failed: {task_type}", str(e))
        finally:
            self.process_scan_queue()

    def extraction_error(self, worker, task_type, err_msg):
        if worker in self.active_scanners:
            self.active_scanners.remove(worker)
        self.handle_critical_error(f"Specialist Extraction Failed: {task_type}", err_msg)
        self.process_scan_queue()

    # REDIRECTED TO V2.0 HUB
    def run_vol_scan(self, plugin_alias, view_widget):
        self.handle_plugin_execute(plugin_alias, "")

    def run_specialist_scan(self, task_type):
        if not self.current_filepath:
            return
        self.run_specialist_scan_internal(task_type)


    def update_ai_artifact_count(self):
        """Syncs the UI counter with session DB state."""
        try:
            results = get_all_scan_results()
            self.view.ai_analyst_view.artifact_counter.setText(f"ARTIFACTS AVAILABLE: {len(results)}")
        except Exception as e:
            print(f"[DEBUG] Failed to update artifact count: {e}")

    def import_error(self, err_msg):
        self.view.dashboard_view.import_btn.setEnabled(True)
        self.view.dashboard_view.progress_bar.hide()
        QMessageBox.critical(self.view, "Import Error", f"An error occurred: {err_msg}")

    def _get_persistent_api_key(self):
        """Retrieves key from 'api_key' file or prompts user if missing/empty."""
        key_file = "api_key"
        if os.path.exists(key_file):
            with open(key_file, "r") as f:
                key = f.read().strip()
                if key:
                    return key

        # If we get here, the key is missing or empty
        key, ok = QInputDialog.getText(self.view, "AI Authentication", 
                                     "Google Gemini API Key required:",
                                     QLineEdit.EchoMode.Password)
        if ok and key.strip():
            with open(key_file, "w") as f:
                f.write(key.strip())
            return key.strip()
        return None

    def generate_ai_report(self):
        if not self.current_filepath:
            QMessageBox.warning(self.view, "No Evidence", "Please import a memory dump first.")
            return
            
        api_key = self._get_persistent_api_key()
        if not api_key:
            return

        # Prepare Context from Session DB
        results = get_all_scan_results()
        if not results:
            QMessageBox.warning(self.view, "No Data", "No forensic artifacts found in session database. Run some scans first.")
            return

        self.view.ai_analyst_view.generate_btn.setEnabled(False)
        self.view.ai_analyst_view.status_label.setText("// GENERATING FORENSIC REPORT...")
        self.view.ai_analyst_view.chat_history.clear()
        
        # Build consolidated context string
        context_parts = []
        for plugin_name, json_data in results:
            data = json.loads(json_data)
            # Take first 30 rows to prevent context window overflow
            sample = data[:30]
            context_parts.append(f"--- PLUGIN: {plugin_name} ---\n{json.dumps(sample, indent=2)}")

        consolidated_ctx = "\n\n".join(context_parts)
        
        from memnet.ai.gemini_client import GeminiClient
        from memnet.controllers.report_worker import AIReportWorker
        
        client = GeminiClient(api_key)
        self.worker = AIReportWorker(client, consolidated_ctx)
        self.worker.finished.connect(self.on_report_finished)
        self.worker.error.connect(self.on_report_error)
        self.worker.start()
        self.active_scanners.append(self.worker)

    def on_report_finished(self, report_text):
        if self.worker in self.active_scanners:
            self.active_scanners.remove(self.worker)
            
        self.view.ai_analyst_view.generate_btn.setEnabled(True)
        self.view.ai_analyst_view.export_btn.setEnabled(True)
        self.view.ai_analyst_view.status_label.setText("// REPORT READY")
        self.view.ai_analyst_view.chat_history.setMarkdown(report_text)
        
    def on_report_error(self, err_msg):
        if self.worker in self.active_scanners:
            self.active_scanners.remove(self.worker)
            
        self.view.ai_analyst_view.generate_btn.setEnabled(True)
        self.view.ai_analyst_view.status_label.setText("// GENERATION FAILED")
        QMessageBox.critical(self.view, "AI Error", f"Report generation failed:\n{err_msg}")
        
    def export_report(self):
        report_text = self.view.ai_analyst_view.chat_history.toPlainText()
        if not report_text:
            QMessageBox.warning(self.view, "No Report", "There is no chat history to export.")
            return
        filepath, _ = QFileDialog.getSaveFileName(self.view, "Export Report", "Forensic_Report.md", "Markdown Files (*.md);;All Files(*)")
        if filepath:
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(report_text)
            QMessageBox.information(self.view, "Export Success", f"Report saved securely to:\n{filepath}")

    def open_in_graph(self, target_pid):
        if not self.current_filepath:
            return
            
        target_pid = str(target_pid)
        self.view.graph_view.clear()
        self.view.graph_view.info_label.setText(f"// ANALYZING RELATIONSHIPS FOR PID {target_pid}")
        
        # Load data from DB
        rows = get_all_scan_results()
        
        ps_data = []
        net_data = []
        for mod_name, json_data in rows:
            if "pslist" in mod_name.lower():
                ps_data = json.loads(json_data)
            elif "netstat" in mod_name.lower():
                net_data = json.loads(json_data)
        
        if not ps_data:
            QMessageBox.warning(self.view, "Missing Data", "No process list found. Execute PSLIST first.")
            return

        # Find the center node
        center_ps = next((p for p in ps_data if str(p.get("PID")) == target_pid), None)
        if not center_ps:
            QMessageBox.warning(self.view, "Error", f"Process {target_pid} not found in recent scan.")
            return
            
        # 1. Add center node
        name = center_ps.get('Name') or center_ps.get('ImageFileName') or "UNKNOWN"
        center_node = self.view.graph_view.add_node(target_pid, f"{name} ({target_pid})", "process", center_ps, (0, 0))
        
        # 2. Add Parent
        ppid = str(center_ps.get("PPID"))
        parent_ps = next((p for p in ps_data if str(p.get("PID")) == ppid), None)
        if parent_ps:
            p_name = parent_ps.get('Name') or parent_ps.get('ImageFileName') or "UNKNOWN"
            self.view.graph_view.add_node(ppid, f"PARENT: {p_name} ({ppid})", "process", parent_ps, (0, -150))
            self.view.graph_view.add_edge(ppid, target_pid)
            
        # 3. Add Children (Spread horizontally)
        children = [p for p in ps_data if str(p.get("PPID")) == target_pid]
        for i, child in enumerate(children):
            c_pid = str(child.get("PID"))
            c_name = child.get('Name') or child.get('ImageFileName') or "UNKNOWN"
            x_off = (i - (len(children)-1)/2) * 150
            self.view.graph_view.add_node(c_pid, f"CHILD: {c_name} ({c_pid})", "process", child, (x_off, 150))
            self.view.graph_view.add_edge(target_pid, c_pid)
            
        # 4. Add Network Connections
        conns = [c for c in net_data if str(c.get("PID")) == target_pid]
        for i, conn in enumerate(conns):
            conn_id = f"net_{target_pid}_{i}"
            label = f"{conn.get('Proto')} {conn.get('ForeignAddr')}"
            x_off = (i - (len(conns)-1)/2) * 150
            self.view.graph_view.add_node(conn_id, label, "network", conn, (x_off, 300))
            self.view.graph_view.add_edge(target_pid, conn_id)

        # 5. Switch to Graph Tab automatically
        self.view.tabs.setCurrentWidget(self.view.graph_view)
        

    def handle_add_graph(self, data):
        # Identify entities for the graph
        pid = data.get("PID", data.get("ProcessId", data.get("OwnerPID")))
        ppid = data.get("PPID", data.get("ParentPID"))
        # Improved Name Resolution: Support 'Owner' field and fallbacks
        name = data.get("Name", data.get("ImageFileName", data.get("Filename", data.get("Owner", "Unknown"))))
        
        if pid:
            # Final chance: if name is still 'Unknown', search the pslist cache for this PID
            if name == "Unknown":
                conn = get_connection()
                cursor = conn.cursor()
                cursor.execute("SELECT results_json FROM scan_results WHERE plugin_name = 'windows.pslist.PsList'")
                ps_row = cursor.fetchone()
                conn.close()
                if ps_row:
                    procs = json.loads(ps_row[0])
                    for p in procs:
                        if str(p.get("PID")) == str(pid):
                            name = p.get("ImageFileName", "Unknown")
                            break

            self.view.graph_view.add_forensic_node("process", str(pid), str(name), metadata=data)
            
            # --- START COMPREHENSIVE DISCOVERY PASS ---
            conn = get_connection()
            cursor = conn.cursor()
            
            # 1. Process Discovery (Parents & Children)
            cursor.execute("SELECT results_json FROM scan_results WHERE plugin_name = 'windows.pslist.PsList'")
            ps_row = cursor.fetchone()
            if ps_row:
                procs = json.loads(ps_row[0])
                
                # A. Identify Parent
                if ppid:
                    for p in procs:
                        if str(p.get("PID")) == str(ppid):
                            p_name = p.get("ImageFileName", "Parent")
                            self.view.graph_view.add_forensic_node("process", str(ppid), str(p_name), metadata=p)
                            self.view.graph_view.add_forensic_edge(str(ppid), str(pid))
                            break
                
                # B. Identify Children
                for p in procs:
                    if str(p.get("PPID")) == str(pid):
                        child_pid = str(p.get("PID"))
                        child_name = p.get("ImageFileName", "Child")
                        self.view.graph_view.add_forensic_node("process", child_pid, child_name, metadata=p)
                        self.view.graph_view.add_forensic_edge(str(pid), child_pid)

            # 2. Network Discovery
            cursor.execute("SELECT results_json FROM scan_results WHERE plugin_name = 'windows.netstat.NetStat'")
            net_row = cursor.fetchone()
            if net_row:
                conns = json.loads(net_row[0])
                for c in conns:
                    c_pid = c.get("PID", c.get("OwnerPID"))
                    if str(c_pid) == str(pid):
                        raddr = c.get("ForeignAddr", c.get("DstIP", "0.0.0.0"))
                        rport = c.get("ForeignPort", c.get("DstPort", ""))
                        state = c.get("State", "UNKNOWN")
                        
                        conn_label = f"{raddr}:{rport}" if rport else str(raddr)
                        conn_id = f"net_{pid}_{conn_label}_{state}" 
                        
                        self.view.graph_view.add_forensic_node("network", conn_id, conn_label, metadata=c)
                        self.view.graph_view.add_forensic_edge(str(pid), conn_id)

            conn.close()
            # --- END DISCOVERY PASS ---

        # Explicit Network Addition: If trigger data is a network row, ensure its node exists
        raddr = data.get("ForeignAddr", data.get("DstIP"))
        if raddr:
            rport = data.get("ForeignPort", data.get("DstPort", ""))
            state = data.get("State", "UNKNOWN")
            conn_label = f"{raddr}:{rport}" if rport else str(raddr)
            conn_id = f"net_{pid}_{conn_label}_{state}"
            self.view.graph_view.add_forensic_node("network", conn_id, conn_label, metadata=data)
            if pid:
                self.view.graph_view.add_forensic_edge(str(pid), conn_id)
        
        # Switch to graph tab to show progress
        self.view.tabs.setCurrentWidget(self.view.graph_view)

    def handle_node_click(self, node_type, node_id):
        if node_type == "process":
            self.view.tabs.setCurrentWidget(self.view.process_view)
        elif node_type == "network":
            self.view.tabs.setCurrentWidget(self.view.network_view)

    def handle_progress_update(self, percent, description):
        self.view.progress_bar.setValue(percent)
        self.view.progress_bar.setVisible(percent < 100)
        self.view.progress_label.setText(f"// {description.upper()}")
        
        # Dashboard Sync
        self.view.dashboard_view.progress_bar.setValue(percent)
        self.view.dashboard_view.progress_bar.setVisible(percent < 100)
        
        if percent >= 100:
            self.view.progress_label.setText("READY")
    def handle_tor_investigation(self):
        """
        Surgical strike for Tor Browser artifacts.
        Triggers Registry, Network, and File scouts.
        """
        if not self.current_filepath:
            QMessageBox.warning(self.view, "Error", "Please import a memory dump first.")
            return

        self.view.tor_view.clear()
        self.view.tor_view.scan_btn.setEnabled(False)
        self.view.tor_view.scan_btn.setText("⏳ SCOUTING DARK WEB ARTIFACTS...")
        
        # 1. Execution Traces (Registry Scout)
        # We trigger hivelist then printkey for specific Tor paths
        self.run_tor_scout()

    def run_tor_scout(self):
        from memnet.controllers.specialist_worker import TorScoutWorker
        self.worker = TorScoutWorker(self.current_filepath)
        self.worker.progress.connect(lambda p: None) # Silent progress for now
        self.worker.finished.connect(self.on_tor_scout_finished)
        self.worker.error.connect(self.on_scan_error)
        self.worker.start()

    def on_tor_scout_finished(self, results):
        self.view.tor_view.scan_btn.setEnabled(True)
        self.view.tor_view.scan_btn.setText("🚀 INVESTIGATE DARK WEB ACTIVITY")
        
        # Results is a dict with categories
        for category, artifacts in results.items():
            cat_item = self.view.tor_view.add_category(category)
            for art in artifacts:
                self.view.tor_view.add_artifact(
                    cat_item, 
                    art.get("name", "Unknown"), 
                    art.get("value", "N/A"), 
                    art.get("source", "Memory")
                )
        
        QMessageBox.information(self.view, "Tor Investigation", "Surgical scout complete. Check the artifacts tree.")

    def on_scan_error(self, module, error):
        self.view.tor_view.scan_btn.setEnabled(True)
        self.view.tor_view.scan_btn.setText("🚀 INVESTIGATE DARK WEB ACTIVITY")
        QMessageBox.critical(self.view, "Scout Failed", f"Tor Scout Error ({module}): {error}")
