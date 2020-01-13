# Implement your module commands in this script.

Get-ChildItem $PSScriptRoot\*.ps1 | ForEach-Object {
    write-verbose "dot sourcing $($_.FullName)"
    . $_.FullName
}

# Export only the functions using PowerShell standard verb-noun naming.
# Be sure to list each exported functions in the FunctionsToExport field of the module manifest file.
# This improves performance of command discovery in PowerShell.
# Export-ModuleMember -Function *-*
