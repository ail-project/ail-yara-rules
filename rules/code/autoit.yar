rule test_autoit
{
    meta:
        author = "kevthehermit"
        info = "Part of PasteHunter"
        reference = "https://github.com/kevthehermit/PasteHunter"

    strings:
        $tray = "NoTrayIcon" nocase wide ascii fullword
        $a = "iniread" nocase wide ascii fullword
        $b = "fileinstall" nocase wide ascii fullword
        $c  = "EndFunc" nocase wide ascii fullword
        $d = "FileRead" nocase wide ascii fullword
        $e = "DllStructSetData" nocase wide ascii fullword
        $f = "Global Const" nocase wide ascii fullword
        $g = "Run(@AutoItExe" nocase wide ascii fullword
        $h = "StringReplace" nocase wide ascii fullword
        $i = "filewrite" nocase wide ascii fullword



    condition:
        ($tray and 3 of them) or (5 of them)
}
