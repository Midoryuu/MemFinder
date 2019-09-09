rule ReverseShellSignature
{
    meta:
        info = "Signature definition of a specific homemade fileless malware running through powershell"

    strings:
        $a = /while\(\(\$count = \$netStream\.Read\(\$buffer, 0, \$buffer\.Length\)\) -ne 0\)(\s*)\{(\s*)\$cmd = \$utf8\.GetString\(\$buffer, 0, \$count\);(\s*)\$result = \(Invoke-Expression \$cmd 2>&1 \| Out-String \);(\s*)\$response = \$utf8\.GetBytes\(\$result\);(\s*)\$netStream\.Write\(\$response, 0, \$response\.Length\);(\s*)\$netStream\.Flush\(\);(\s*)\}/ wide

    condition:
        all of them
}