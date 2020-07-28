rule b64_zip
{
    meta:
        author = "@KevTheHermit"
        info = "Part of PasteHunter"
        reference = "https://github.com/kevthehermit/PasteHunter"

    strings:
        $b64_zip = "UEs"
    condition:
        $b64_zip at 0

}
