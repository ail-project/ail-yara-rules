rule Salesforce {
    meta:
        author = "Dylan Katz (@Plazmaz)"
        description = "Generic salesforce Credentials (Created as part of PasteHunter)"
        reference = "https://github.com/techgaun/github-dorks"
        date = "09/15/19"
    strings:
        $ = "SF_USERNAME" nocase
        $ = "salesforce" nocase
    condition:
        all of them
}
