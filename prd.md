This Product Requirements Document (PRD) is designed to be a comprehensive blueprint. You can hand this directly to an engineer (or an AI agent like Antigravity) to begin architecture and coding.

🛡️ PRD: Project "MFT(memory forensic TOOL)"
Sub-title: AI-Augmented Volatile Memory Analysis Suite

Target: Digital Forensic Investigators & Cyber Security Researchers

1. Executive Summary
   AuraForensics is a GUI-based digital forensics tool designed to simplify memory analysis using the Volatility 3 framework. It bridges the gap between raw data extraction and actionable intelligence by integrating Gemini 3 Flash to generate automated, professional-grade forensic reports in Markdown format.
2. Technical Stack
   Core Engine: Python 3.11+

Forensic Framework: Volatility 3 (volatility3 library)

GUI Framework: PyQt6 (utilizing a Model-View-Controller architecture)

AI Integration: Google GenAI SDK (Gemini 3 Flash)

Storage: SQLite (for case management and result caching)

Threading: QThread / QThreadPool for non-blocking UI operations

3. Functional Requirements
   3.1 Evidence Acquisition & Management
   File Support: Must accept .raw, .mem, .vmem, .bin, and .E01 (via libewf).

Integrity: On file load, the tool must calculate MD5 and SHA-256 hashes and log them in the Case Header.

Case Profiling: Users can input Case Name, Investigator ID, and timestamp.

3.2 Core Forensic Modules (Volatility 3 Wrappers)
The tool must implement the following "One-Click" analysis modules:

Process Insights: windows.pslist, windows.pstree, and windows.psscan (to find hidden/unlinked processes).

Command & Control: windows.cmdline to see process execution arguments.

Network Intelligence: windows.netstat (IPs, Ports, Protocols) integrated with a local Geo-IP lookup.

Credential Hunter: windows.hashdump and windows.cachedump.

Malware Detection: windows.malfind to detect injected code/VAD anomalies.

3.3 Advanced Specialist Modules
Tor Forensic Module: * Search for .onion patterns in memory strings.

Identify Tor-specific processes (e.g., tor.exe).

Browser Artifacts: Extracting URL strings and form-data from RAM buffers.

3.4 AI Forensic Analyst (Gemini Integration)
Context Aggregator: A backend function that compiles text outputs from pstree, netstat, and malfind into a single context window.

API Interface: A dedicated "AI Analysis" tab where users provide a Gemini API Key.

Automated Prompting: Uses a system prompt to ask Gemini to:

Highlight high-risk anomalies.

Correlate network connections with suspicious processes.

Summarize findings in a Markdown (.md) report.

Privacy Guard: A feature to mask specific PII (Personally Identifiable Information) before sending data to the API.

4. UI/UX Requirements
   Main Dashboard: A sidebar navigation (Summary, Processes, Network, AI Analyst, Hex Viewer).

The Hex Viewer: A dedicated panel that allows raw bytes viewing of selected process memory.

Responsiveness: All forensic scans must run in a background thread. A progress bar must be visible to prevent "Application Not Responding" errors.

Output Consistency: Tables must be sortable and searchable (e.g., search for "svchost" to filter processes).

5. Non-Functional Requirements
   Scalability: Must handle memory dumps up to 32GB using memory-mapped file access.

Auditability: Every action taken by the user must be logged in a session_audit.log.

Portability: The final tool should be packagable as a standalone executable (using PyInstaller).

6. Action Plan for Development
   Phase 1: The Core (Weeks 1-2)
   Set up Python environment and Volatility 3 dependencies.

Build the GUI "Shell" in PyQt6 with Case Management logic.

Implement MD5/SHA256 hashing on file import.

Phase 2: The Data Layers (Weeks 3-4)
Integrate Volatility plugins as Python modules (not subprocesses).

Map output to PyQt QTableWidgets.

Implement SQLite database to save "Scanned States."

Phase 3: AI & Reporting (Weeks 5-6)
Develop the Gemini API client.

Refine the "Forensic Summary" system prompt.

Add the "Export to Markdown" functionality.

Phase 4: Testing & Finalization (Weeks 7-8)
Test with known malware-infected memory dumps (e.g., Stuxnet or Cridex samples).

Validate Tor extraction accuracy.

Generate the final lab report/documentation.

Note for Developer: Ensure the google-genai client is initialized within a QThread to maintain UI fluidness during the 1M+ token context processing. Use Gemini 3 Flash for the best balance of context length and speed.
