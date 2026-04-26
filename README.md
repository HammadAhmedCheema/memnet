# AuraForensics v2.8 🕵️‍♂️

**AuraForensics** is a state-of-the-art memory forensics platform developed for Phase 4 of the University Digital Forensics program. It is designed for **transient, zero-footprint investigations**, combining the power of **Volatility 3** with a proprietary **Gemini-powered AI Analyst** for real-time artifact correlation.

---

## 🚀 Tool Overview

Unlike traditional forensic suites that rely on persistent databases, AuraForensics utilizes a **Transient SQL Architecture**. Forensic results are stored in a volatile session buffer that is automatically securely deleted upon application exit, ensuring that sensitive evidence does not persist on the analyst's machine.

### Key Capabilities

- **Automated Memory Triage**: Out-of-the-box support for `PsList`, `NetStat`, `Malfind`, and `Registry` analysis.
- **AI-Driven Specialists**: Specialized extraction of Browser History, URLs, and Tor (Deep Web) signatures using stitched VAD context.
- **Relationship Mapping**: Dynamic visualization of process-to-network-to-file relationships.
- **Evidence Integrity**: Automated MD5 and SHA256 hashing of all ingested memory dumps.

---

## 🏗️ Installation & Prerequisites

AuraForensics requires **Python 3.10 or 3.11**.

### 📋 Prerequisites

- **OS**: Linux (Kali Linux or Ubuntu 22.04+ recommended)
- **Pip**: Python package manager
- **Internet Connection**: Required for AI Analyst integration and symbol downloads.

### ⚙️ Environment Setup

It is highly recommended to use a virtual environment to prevent dependency conflicts.

```bash
# Navigate to project root and create venv
python3 -m venv .venv
source .venv/activate

# Install core dependencies
pip install --upgrade pip
pip install -r requirements.txt
```

### 🧩 Critical Components

The following packages are essential for the forensic engine:

- **volatility3**: Core forensic framework.
- **yara-python**: Memory signature scanning.
- **capstone**: Instruction disassembly.
- **PyQt6**: Graphical Interface.

---

## 🔑 AI Analyst Configuration

AuraForensics currently exclusively supports the **Google Gemini API** for intelligent artifact correlation. Other AI providers (e.g., OpenAI, Anthropic) are not supported in the current version.

1. Obtain an API Key from the [Google AI Studio](https://aistudio.google.com/).
2. Create a file named `api_key` in the root directory:

   ```bash
   echo "YOUR_API_KEY_HERE" > api_key
   ```

3. Alternatively, the application will prompt you for a key via the GUI if the file is missing.

---

## 🖥️ Execution Steps

To launch the Forensic Suite:

```bash
python -m auraforensic.main
```

### Typical Workflow

1. **Ingest Evidence**: Load a `.raw`, `.mem`, or `.E01` memory dump via the Dashboard.
2. **Automated Triage**: The tool automatically starts Phase 1-3 triage (Processes, Network, Specialist Extraction).
3. **AI Consultation**: Interact with the **AI Specialist** to correlate findings or generate forensic reports.
4. **Session Exit**: Close the application; the transient session database (`mft_session.db`) is automatically flushed.

---

## 🌐 Platform Compatibility

| Platform | Status | Context |
| :--- | :--- | :--- |
| **Linux (Kali/Ubuntu)** | ✅ Fully Supported | Primary development environment. Recommended. |
| **Windows 10/11** | ⚠️ Supported | Requires Python 3.10 and Volatility 3 binaries. |
| **macOS** | ⚠️ Supported | Limited support for specialized memory formats. |

---

## 🆘 Troubleshooting

- **ModuleNotFoundError (auraforensic.xxx)**: Ensure you are running the tool with `python -m auraforensic.main` from the project root.
- **Volatility Layer Failure**: Verify your symbol server configuration or ensure you are using a supported Windows memory image.
- **AI Analyst Timeout**: Check your internet connection and ensure your Gemini API key has sufficient quota.

---

*Developed for the Digital Forensics Course (Sem 6).*
