rule twitter_api
{
    meta:
        author = "@KevTheHermit"
        info = "Part of PasteHunter"
        reference = "https://github.com/kevthehermit/PasteHunter"

    strings:
        $a = "consumer_key" nocase
        $b = "consumer_secret" nocase
        $c = "access_token" nocase
    condition:
        all of them

}
