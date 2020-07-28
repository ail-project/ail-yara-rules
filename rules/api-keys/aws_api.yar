rule aws_api
{
    meta:
        author = "@ntddk"
        info = "Part of PasteHunter"
        reference = "https://github.com/kevthehermit/PasteHunter"

    strings:
        $a = /AKIA[0-9A-Z]{16}/
    condition:
        any of them
}
