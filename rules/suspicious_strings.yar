rule Suspicious_Ransomware_Note
{
    meta:
        description = "Flags common ransomware note phrasing"
        score = 60
        author = "you"

    strings:
        $s1 = "your files have been encrypted" nocase
        $s2 = "decrypt your files" nocase
        $s3 = "bitcoin" nocase
        $s4 = "pay the ransom" nocase

    condition:
        2 of them
}

rule Suspicious_PowerShell_Download
{
    meta:
        description = "Flags scripts that silently download and execute code"
        score = 70
        author = "you"

    strings:
        $s1 = "IEX" nocase
        $s2 = "DownloadString" nocase
        $s3 = "-EncodedCommand" nocase
        $s4 = "Invoke-Expression" nocase

    condition:
        2 of them
}