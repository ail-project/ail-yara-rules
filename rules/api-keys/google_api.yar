rule google_api
{
    meta:
        author = "@KevTheHermit"
        info = "Part of PasteHunter"
        reference = "https://github.com/kevthehermit/PasteHunter"

    strings:
        $a = /\bAIza.{35}\b/
    condition:
        any of them
}

