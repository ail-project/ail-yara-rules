rule db_structure
{
    meta:
        author = "@KevTheHermit"
        info = "Part of PasteHunter"
        reference = "https://github.com/kevthehermit/PasteHunter"

    strings:
        $a = "CREATE TABLE" nocase
        $b = "INSERT INTO" nocase
        $c = "VALUES" nocase
        $d = "ENGINE" nocase
        $e = "CHARSET" nocase
        $f = "NOT NULL" nocase
        $g = "varchar" nocase
        $h = "PRIMARY KEY"

    condition:
        5 of them
}
