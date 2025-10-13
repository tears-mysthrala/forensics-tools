# AdvancedMemory.ps1 - Advanced Memory Forensics Module
# This module imports all advanced memory forensics functions from separate modules

# Import advanced memory modules
. "$PSScriptRoot\VolatilityPlugins.ps1"
. "$PSScriptRoot\MemoryDump.ps1"
. "$PSScriptRoot\MemoryTimeline.ps1"
. "$PSScriptRoot\MemoryStrings.ps1"
. "$PSScriptRoot\MemoryArtifacts.ps1"
. "$PSScriptRoot\MemoryAnalysis.ps1"