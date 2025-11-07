# AWS Security Scanner - PowerShell Wrapper
param(
    [Parameter(ValueFromRemainingArguments=$true)]
    $Arguments
)

$env:PYTHONIOENCODING = "utf-8"
python main.py @Arguments

