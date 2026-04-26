# Categories as defined in the PRD v2.0

PLUGIN_MAP = {
    # Process Intelligence
    "Active Processes": "windows.pslist.PsList",
    "Hidden Processes": "windows.psscan.PsScan",
    "Command Lines": "windows.cmdline.CmdLine",
    
    # Network & Comms
    "Active Connections": "windows.netstat.NetStat",
    "Deep Network Scan": "windows.netscan.NetScan",
    
    # Threat Hunting
    "Injected Code (Malfind)": "windows.malfind.Malfind",
    "Process Hollowing": "windows.hollowprocesses.HollowProcesses",
    
    # Registry & Persistence
    "Loaded Hives": "windows.registry.hivelist.HiveList",
    "Execution History": "windows.registry.userassist.UserAssist",
    "Query Specific Key": "windows.registry.printkey.PrintKey",
    
    # System & Extraction
    "Scan Open Files": "windows.filescan.FileScan",
    "Dump Executable": "windows.pedump.PEDump",
    "Dump Hashes (Hashdump)": "windows.hashdump.Hashdump"
}

TAB_CONFIG = {
    "Process Intelligence": ["Active Processes", "Hidden Processes", "Command Lines"],
    "Network & Comms": ["Active Connections", "Deep Network Scan"],
    "Threat Hunting": ["Injected Code (Malfind)", "Process Hollowing"],
    "Registry & Persistence": ["Loaded Hives", "Execution History", "Query Specific Key"],
    "System & Extraction": ["Scan Open Files", "Dump Executable", "Dump Hashes (Hashdump)"]
}
