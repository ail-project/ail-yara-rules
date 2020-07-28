rule ducky_code
{
    meta:
        author = "@KevTheHermit"
        info = "Part of PasteHunter"
        reference = "https://github.com/kevthehermit/PasteHunter"

    strings:
        $a1 = "DELAY"
        $a2 = "GUI r"
        $a3 = "STRING"
        $a4 = "ENTER"
        $a5 = "DEFAULTDELAY"
        $a6 = "WINDOWS"
        $a7 = "SHIFT"
    condition:
        4 of them
}
