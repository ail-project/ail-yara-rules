rule b64_gzip
{
    meta:
        author = "@KevTheHermit"
        info = "Part of PasteHunter"
        reference = "https://github.com/kevthehermit/PasteHunter"

    strings:
        $b64_gzip = "H4sI"
    condition:
        $b64_gzip at 0

}
