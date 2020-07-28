rule generic_api
{
    meta:
        author = "@KevTheHermit"
        info = "Part of PasteHunter"
        reference = "https://github.com/kevthehermit/PasteHunter"

    strings:
        $a1 = "apikey" nocase
        $a2 = "api_key" nocase
        $hash32 = /\b[a-fA-F\d]{32}\b/
        $hash64 = /\b[a-fA-F\d]{64}\b/
        $n1 = "#EXTINF"
        $n2 = "m3u8"
        $n3 = "Chocolatey is running"

    condition:
        (any of ($a*)) and (any of ($hash*)) and (not any of ($n*))

}
