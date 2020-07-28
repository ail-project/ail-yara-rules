rule Shodan {
    meta:
        author = "Dylan Katz (@Plazmaz)"
        description = "Shodan API Keys (Created as part of PasteHunter)"
        reference = "https://github.com/techgaun/github-dorks"
        date = "09/15/19"
    strings:
        $ = /shodan_api_key: [a-zA-Z0-9]+/ nocase
        $ = /shodan_api_key=[a-zA-Z0-9]+/ nocase
    condition:
        any of them
}
