rule github_api
{
    meta:
        author = "@ntddk"
        info = "Part of PasteHunter"
        reference = "https://github.com/kevthehermit/PasteHunter"

    strings:
        $a = /[g|G][i|I][t|T][h|H][u|U][b|B].*[[\'|"]0-9a-zA-Z]{35,40}[\'|"]/
    condition:
        any of them
}
