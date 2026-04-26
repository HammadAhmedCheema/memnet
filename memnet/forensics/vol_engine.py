import os
import logging
import json
from volatility3.framework import contexts, automagic, plugins, interfaces
from volatility3.framework.automagic import stacker
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import renderers

from volatility3.plugins.windows import pslist, pstree, psscan, netstat, netscan, vadyarascan, vadinfo, malfind, hollowprocesses, filescan, pedump, cmdline
from volatility3.plugins.windows.registry import hashdump, cachedump, hivelist, userassist, printkey
from volatility3.plugins import yarascan

# Suppress overly verbose logging from volatility
logging.getLogger("volatility3").setLevel(logging.ERROR)

PLUGIN_MAP = {
    "windows.pslist.PsList": pslist.PsList,
    "windows.pstree.PsTree": pstree.PsTree,
    "windows.psscan.PsScan": psscan.PsScan,
    "windows.cmdline.CmdLine": cmdline.CmdLine,
    "windows.netstat.NetStat": netstat.NetStat,
    "windows.netscan.NetScan": netscan.NetScan,
    "windows.hashdump.Hashdump": hashdump.Hashdump,
    "windows.cachedump.Cachedump": cachedump.Cachedump,
    "windows.malfind.Malfind": malfind.Malfind,
    "windows.hollowprocesses.HollowProcesses": hollowprocesses.HollowProcesses,
    "windows.vadyarascan.VadYaraScan": vadyarascan.VadYaraScan,
    "windows.vadinfo.VadInfo": vadinfo.VadInfo,
    "windows.registry.hivelist.HiveList": hivelist.HiveList,
    "windows.registry.userassist.UserAssist": userassist.UserAssist,
    "windows.registry.printkey.PrintKey": printkey.PrintKey,
    "windows.filescan.FileScan": filescan.FileScan,
    "windows.pedump.PEDump": pedump.PEDump
}


class RuntimeProgress:
    def __init__(self, callback=None):
        self.callback = callback

    def __call__(self, progress, description=None):
        if self.callback:
            self.callback(int(progress), description or "Processing...")

class NullFileHandler(interfaces.plugins.FileHandlerInterface):
    def _get_final_filename(self):
        return os.path.join(os.getcwd(), self.preferred_filename)

class VolatilityEngine:
    def __init__(self, filepath, progress_callback=None):
        self.filepath = filepath
        self.progress_callback = progress_callback

    def run_plugin(self, plugin_name, plugin_args=None):
        """
        Runs a volatility3 plugin directly using the framework context.
        Returns a list of dictionaries representing the row data.
        """
        if not os.path.exists(self.filepath):
            raise FileNotFoundError(f"Memory dump not found: {self.filepath}")

        # Construct context and point automagic file layer directly to path
        ctx = contexts.Context()
        single_location = requirements.URIRequirement.location_from_file(self.filepath)
        ctx.config['automagic.LayerStacker.single_location'] = single_location
        
        if plugin_name not in PLUGIN_MAP:
            raise KeyError(f"Plugin {plugin_name} not found in available list.")
            
        plugin_opt = PLUGIN_MAP[plugin_name]
        
        # Insert specific plugin arguments
        if plugin_args:
            if isinstance(plugin_args, str):
                plugin_args = plugin_args.strip()
                if not plugin_args:
                    pass # Handled below
                elif "=" in plugin_args and not plugin_args.startswith("rule"):
                    # Basic parser for key=value pairs
                    import re
                    # Match key=value where value can be quoted
                    matches = re.findall(r'(\w+)=([^"\s]+|"[^"]*"|\'[^\']*\')', plugin_args)
                    if matches:
                        for k, v in matches:
                            clean_v = v.strip('"').strip("'")
                            # Try to convert to int if possible
                            if clean_v.isdigit():
                                clean_v = int(clean_v)
                            ctx.config[f"plugins.{plugin_opt.__name__}.{k}"] = clean_v
                    else:
                        # Fallback for single value
                        self._apply_heuristic_param(ctx, plugin_name, plugin_opt, plugin_args)
                else:
                    self._apply_heuristic_param(ctx, plugin_name, plugin_opt, plugin_args)
            elif isinstance(plugin_args, dict):
                for k, v in plugin_args.items():
                    ctx.config[f"plugins.{plugin_opt.__name__}.{k}"] = v

        # Final check for YARA rules to prevent Volatility ValueError
        if "YaraScan" in plugin_name:
            rules_key = f"plugins.{plugin_opt.__name__}.yara_rules"
            file_key = f"plugins.{plugin_opt.__name__}.yara_file"
            if not ctx.config.get(rules_key) and not ctx.config.get(file_key):
                # Inject a default rule that finds common strings but does nothing expensive
                ctx.config[rules_key] = "rule DefaultDiscovery { condition: true }"
        
        # Configure and run automagics
        automagics = automagic.available(ctx)
        automagics = automagic.choose_automagic(automagics, plugin_opt)

        if ctx.config.get("automagic.LayerStacker.stackers", None) is None:
            ctx.config["automagic.LayerStacker.stackers"] = stacker.choose_os_stackers(plugin_opt)

        constructed = plugins.construct_plugin(
            ctx,
            automagics,
            plugin_opt,
            "plugins",
            RuntimeProgress(self.progress_callback),
            NullFileHandler
        )
            
        # Construct and run plugin
        tree_grid = constructed.run()
        
        return self._extract_tree_data(tree_grid)

    def _apply_heuristic_param(self, ctx, plugin_name, plugin_opt, plugin_args):
        """Maintains simple string-to-config mapping for legacy one-box parameter input."""
        if "PrintKey" in plugin_name:
            ctx.config[f"plugins.{plugin_opt.__name__}.key"] = plugin_args
        elif "PEDump" in plugin_name:
            try:
                ctx.config[f"plugins.{plugin_opt.__name__}.pid"] = int(plugin_args)
            except ValueError:
                pass
        elif "VadYaraScan" in plugin_name:
            ctx.config[f"plugins.{plugin_opt.__name__}.yara_rules"] = plugin_args

    def get_vad_map(self):
        """
        Runs windows.vadinfo to get a mapping of memory regions for all processes.
        """
        results = self.run_plugin("windows.vadinfo.VadInfo")
        vad_map = []
        for row in results:
            try:
                # Volatility 3 vadinfo typically provides virtual offsets and types
                # To correlate with physical offsets from YARA, we need the layer info
                # For this simplified version, we'll store PID and the Virtual range.
                # Note: True physical-to-virtual mapping is complex in Vol3, 
                # but we can use PIDs and VAD tags for clinical correlation.
                vad_map.append({
                    "PID": row.get("PID"),
                    "Start": int(row.get("Start", 0), 16) if isinstance(row.get("Start"), str) else 0,
                    "End": int(row.get("End", 0), 16) if isinstance(row.get("End"), str) else 0,
                    "Tag": row.get("Tag", "Unknown")
                })
            except Exception:
                continue
        return vad_map

    def _extract_tree_data(self, tree_grid):
        results = []
        columns = [col.name for col in tree_grid.columns]
        
        def visitor(node, acc):
            row = {}
            for col_idx, item in enumerate(node.values):
                col_name = columns[col_idx]
                value = item
                
                # Format to JSON serializable objects
                if isinstance(value, renderers.BaseAbsentValue):
                    value = "N/A"
                elif isinstance(value, bytes):
                    value = value.hex()
                elif hasattr(value, '__str__'):
                    value = str(value)
                    
                row[col_name] = value
            results.append(row)
            return acc
            
        tree_grid.populate(visitor)
        return results
