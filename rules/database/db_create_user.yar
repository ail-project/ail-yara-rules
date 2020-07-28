rule db_create_user
{
    meta:
        author = "@KevTheHermit"
        info = "Part of PasteHunter"
        reference = "https://github.com/kevthehermit/PasteHunter"

    strings:
        $a = "GRANT ALL PRIVILEGES" nocase
        $b = "IDENTIFIED BY" nocase
        $c = "GRANT SELECT" nocase
        $d = "CREATE USER" nocase

    condition:
        2 of them
}
