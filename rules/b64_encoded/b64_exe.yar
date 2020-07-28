rule b64_exe
{
    meta:
        author = "@KevTheHermit"
        info = "Part of PasteHunter"
        reference = "https://github.com/kevthehermit/PasteHunter"

    strings:
        $b64_exe = /\bTV(oA|pB|pQ|qA|qQ|ro)/
        // Double b64 = VFZxUU
    condition:
        $b64_exe at 0

}
