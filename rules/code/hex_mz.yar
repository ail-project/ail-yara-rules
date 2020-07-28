rule test_hex_MZ
{
    meta:
        author = "kevthehermit"
        info = "Part of PasteHunter"
        reference = "https://github.com/kevthehermit/PasteHunter"

    strings:
        $mz_hex  = "4d5a" nocase wide ascii

    condition:
        $mz_hex at 0

}
