rule b64_rar
{
    meta:
        author = "@KevTheHermit"
        info = "Part of PasteHunter"
        reference = "https://github.com/kevthehermit/PasteHunter"

    strings:
        $b64_rar = "UmFy"
    condition:
        $b64_rar at 0

}
