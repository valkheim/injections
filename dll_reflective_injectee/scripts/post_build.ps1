Param (
    [Parameter(Mandatory=$true,HelpMessage="Input file path")][string]$Path,
    [Parameter(Mandatory=$true,HelpMessage="Output directory")][string]$Out
)

dumpbin.exe /symbols "$Path" > "$Out\symbols.txt"
dumpbin.exe /headers "$Path" > "$Out\headers.txt"
dumpbin.exe /imports "$Path" > "$Out\imports.txt"
dumpbin.exe /exports "$Path" > "$Out\exports.txt"