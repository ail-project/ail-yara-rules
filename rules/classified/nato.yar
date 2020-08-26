rule nato
{
    meta:
        author = "@adulau"
        info = "Part of ail-yara-rules"
        reference = "https://github.com/ail-project/ail-yara-rules"

    strings:
        $a1 = "COSMIC TOP SECRET" fullword wide ascii nocase
        $a2 = "NATO SECRET" fullword wide ascii nocase
        $a3 = "ATOMAL" fullword wide ascii nocase
        $a4 = "NATO CONFIDENTIAL" fullword wide ascii nocase
        $a5 = "NATO RESTRICTED" fullword wide ascii nocase
        $a6 = "THIS DOCUMENT CONTAINS NATO CLASSIFIED INFORMATION" fullword wide ascii nocase
        $a7 = "NATO UNCLASSIFIED - INTERNAL" fullword wide ascii nocase
        $a8 = /Tres Secret Cosmic/ fullword wide ascii nocase
        $a9 = "Secret OTAN" fullword wide ascii nocase
        $a10 = "Confidentiel OTAN" fullword wide ascii nocase
        $a11 = "Diffusion restreinte OTAN" fullword wide ascii nocase
        $a12 = /COSMIC TOP SECRET.{1,10}BOHEMIA/ fullword wide ascii nocase     #potentially remove since it should be caught by the next one
                                                                                #some documents mention a dash between COSMIC TOP SECRET and BOHEMIA but some don't. Trying to catch both with regexp.
        $a13 = /NATO SECRET.{1,10}BOHEMIA/ fullword wide ascii nocase
        $a14 = /NATO CONFIDENTIAL.{1,10}BOHEMIA/ fullword wide ascii nocase
        $a15 = /COSMIC TOP SECRET.{1,10}BALK/ fullword wide ascii nocase     #potentially remove since it should be caught by the next one
                                                                                #some documents mention a dash between COSMIC TOP SECRET and BALK but some don't. Trying to catch both with regexp.
        $a16 = /NATO SECRET.{1,10}BALK/ fullword wide ascii nocase
        $a17 = /NATO CONFIDENTIAL.{1,10}BALK/ fullword wide ascii nocase

    condition:
        1 of ($a*)

}
