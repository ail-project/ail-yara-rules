rule us
{
    meta:
        author = "@adulau"
        info = "Part of ail-yara-rules"
        reference = "https://github.com/ail-project/ail-yara-rules"

    strings:
        $a1 = "NOT RELEASABLE TO FOREIGN NATIONALS" fullword wide ascii nocase
        $a2 = "CAUTION - PROPRIETARY INFORMATION INVOLVED" fullword wide ascii nocase
        $a3 = "FORMERLY RESTRICTED DATA" fullword wide ascii nocase
        $a4 = "CRITICAL NUCLEAR WEAPON DESIGN INFORMATION" fullword wide ascii nocase
        $a5 = "DOD or DOE CONTROLLED NUCLEAR INFORMATION" fullword wide ascii nocase
        $a6 = "TOP SECRET//" fullword wide ascii nocase
        $a7 = "SECRET//" fullword wide ascii nocase
        $a8 = "CONFIDENTIAL//" fullword wide ascii nocase
        $a9 = "TALENT KEYHOLE" fullword wide ascii nocase
        $a10 = "SPECIAL ACCESS REQUIRED-" fullword wide ascii nocase
        $a11 = "ORIGINATOR CONTROLLED" fullword wide ascii nocase
        $a12 = "CONTROLLED IMAGERY" fullword wide ascii nocase
        $a13 = "SOURCES AND METHODS INFORMATION" fullword wide ascii nocase
        $a14 = "NOT RELEASABLE TO FOREIGN NATIONALS" fullword wide ascii nocase
        $a20 = "DEA SENSITIVE" fullword wide ascii nocase
        $a22 = "LAW ENFORCEMENT SENSITIVE" fullword wide ascii nocase

    condition:
        1 of ($a*)

}
