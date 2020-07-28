rule slack_api
{
    meta:
        author = "@ntddk"
        info = "Part of PasteHunter"
        reference = "https://github.com/kevthehermit/PasteHunter"

    strings:
        $a = /(xox(p|b|o|a)-[0-9]{9,12}-[0-9]{9,12}-[0-9]{9,12}-[a-z0-9]{32})/
        $b = "hooks.slack.com" nocase
    condition:
        any of them
}
