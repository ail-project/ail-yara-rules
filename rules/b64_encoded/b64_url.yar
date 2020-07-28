rule b64_url
{
    meta:
        author = "@KevTheHermit"
        info = "Part of PasteHunter"
        reference = "https://github.com/kevthehermit/PasteHunter"

    strings:
        $a1 = "aHR0cDov" // http/s
        $a2 = "SFRUUDov" // HTTP/S
        $a3 = "d3d3Lg" // www.
        $a4 = "V1dXLg" // WWW.

        // ignore vendor certs in this rule. The certs rule will pick them up if we want them
        $not1 = "GlobalSign Root CA" nocase

        // Ignore data: uris. These are common in html, css, and svg files.
        $not2 = /data:[a-z0-9\/]+;(base64,)?aHR0cDov/ nocase
        $not3 = /data:[a-z0-9\/]+;(base64,)?SFRUUDov/ nocase
        $not4 = /data:[a-z0-9\/]+;(base64,)?d3d3Lg/ nocase
        $not5 = /data:[a-z0-9\/]+;(base64,)?V1dXLg/ nocase

    condition:
        any of ($a*) and not any of ($not*)

}
