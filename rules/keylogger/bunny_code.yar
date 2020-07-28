rule bunny_code
{
    meta:
        author = "@KevTheHermit"
        info = "Part of PasteHunter"
        reference = "https://github.com/kevthehermit/PasteHunter"

    strings:
        $a1 = "ATTACKMODE"
        $a2 = "QUACK"
        $a3 = "ECM_ETHERNET"
        $a4 = "RNDIS_ETHERNET"
        $a5 = "LED"
        $a6 = "GET SWITCH_POSITION"
        $a7 = "REQUIRETOOL"
    condition:
        4 of them
}
