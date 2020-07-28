rule b64_elf
{
    meta:
        author = "@KevTheHermit"
        info = "Part of PasteHunter"
        reference = "https://github.com/kevthehermit/PasteHunter"

    strings:
        $b64_elf = "f0VM"
    condition:
        $b64_elf at 0

}
