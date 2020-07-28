rule b64_rtf
{
    meta:
        author = "@KevTheHermit"
        info = "Part of PasteHunter"
        reference = "https://github.com/kevthehermit/PasteHunter"

    strings:
        $b64_rtf = "e1xydGY" // {\rtf
    condition:
        $b64_rtf at 0

}
