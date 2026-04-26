# MemNet v2.8 : User Guide 📑

Welcome to the **MemNet User Guide**. This document provides an exhaustive walkthrough of the tool's features, forensic workflows, and specialized modules.

---

## 🧭 The Forensic Lifecycle

A typical investigation in MemNet follows a structured four-phase workflow:

1.  **Ingestion & Hashing**: The analyst selects a memory dump. MemNet automatically calculates its **MD5 and SHA256 hashes** to ensure evidence chain-of-custody and integrity.
2.  **Automated Triage**: Upon ingestion, the tool triggers background workers for **Process Enumeration**, **Socket Analysis**, and **VAD Mapping**.
3.  **Specialist Extraction**: Analysts trigger specialized "Deep Scan" workers to carve for specific artifacts like deep-web (Tor) traces, browser history, and hidden URLs.
4.  **AI Correlation**: The **AI Analyst** is used to synthesize findings from the volatile session database into a coherent intelligence report.

---

## 🖥️ Interface Breakdown (Tabs)

### 1. Dashboard (The Command Center)
- **Status Panel**: Displays the current file path, image hashes, and a real-time progress bar for triage tasks.
- **Artifact Overview**: A high-level summary showing the total count of Processes, Network Connections, and Extracted Credentials.
- **Storage Policy**: Displays the "Transient Session" status, indicating that results are being held in memory and will be flushed on exit.

### 2. Process Manager
- **Capabilities**: View all active processes found in the memory image.
- **Triage Columns**: Includes PID, Parent PID, Name, and Start Time.
- **Interactivity**: Analysts can sort columns or search for suspicious process names.

### 3. Network Discovery
- **Socket Analysis**: Displays all active TCP/UDP connections.
- **Triage Columns**: Shows Local IP/Port, Remote IP/Port, Protocol, and the associated Process ID.
- **Forensic Value**: Essential for identifying Command & Control (C2) traffic or unauthorized data exfiltration.

### 4. Specialist Extraction 🧩
This tab contains high-visibility results from specialized carving modules:
- **Credentials**: Passwords and usernames found in plaintext or memory-mapped files.
- **Browser History**: SQLite artifacts extracted from known browser data structures.
- **URLs**: Carved strings matching URI patterns across process VAD ranges.

### 5. Tor Analyst (Deep Web)
- **Signature Detection**: Specifically scans for artifacts associated with the Tor Browser and Onion routing.
- **Identification**: Flags processes or memory regions that indicate anonymized browsing activity.

### 6. Relationship Graph (Beta)
- **Visualization**: Generates a dynamic graph connecting processes to their network sockets and parent relationships.
- **Interactive Nodes**: Click nodes to view metadata (requires force-directed layout stability).

### 7. AI Specialist (The Aura Intelligence) 🤖
- **Real-Time Context**: The AI Analyst window shows exactly how many "Artifacts are Available" in the current session.
- **Generative Intelligence**: Ask the AI to "Generate a summary of suspicious processes" or "Find any connections to known malicious domains."
- **Tool Access**: The AI can directly query the transient database to perform cross-tab correlation.

---

## 🔍 Forensic Modules Explained

### **Core Engine (Volatility 3 Integration)**
The backbone of the tool. It applies symbols and plugins (PsList, NetStat, Malfind) to provide the base layer of evidence.

### **VAD Specialist**
Analyzes Virtual Address Descriptors to distinguish between executable code and data regions. Used to target specialist extraction where it is most likely to find results (e.g., non-paged pool).

### **Hash Integrity Module**
Calculates cryptographic hashes using Python's `hashlib` at the moment of file selection. Both MD5 and SHA256 are provided for academic and professional standardization.

### **Secure Flush Mechanism**
MemNet maintains a strict **Zero-Persistence Policy**. When the `MainWindow` is closed:
1. All database handles are dropped.
2. The `mft_session.db` file is physically deleted from the local disk.
3. Memory buffers are cleared.

---

## 💡 Pro Tips for Analysts

-   **Wait for Triage**: Specialist extraction works most accurately after Phase 1-3 triage is 100% complete.
-   **AI Prompting**: Use specific prompts like *"Correlate PID 440 with the network connections in the database"* for the best results from the AI Analyst.
-   **Integrity First**: Always record the hashes displayed on the Dashboard before starting your analysis.

---

*MemNet: Advanced Memory Intelligence for Modern Investigations.*
