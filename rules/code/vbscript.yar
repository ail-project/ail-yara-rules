rule test_vbscript
{
    meta:
        author = "kevthehermit"
        info = "Part of PasteHunter"
        reference = "https://github.com/kevthehermit/PasteHunter"

    strings:
        $a = "Function" nocase wide ascii fullword
        $b = "CreateObject" nocase wide ascii fullword
        $c  = "Wscript" nocase wide ascii fullword
        $d = "As Long" nocase wide ascii fullword
        $e = "run" nocase wide ascii fullword
        $f = "for each" nocase wide ascii fullword
        $g = "end function" nocase wide ascii fullword
        $h = "NtAllocateVirtualMemory" nocase wide ascii fullword
        $i = "NtWriteVirtualMemory" nocase wide ascii fullword


    condition:
        5 of them
}
