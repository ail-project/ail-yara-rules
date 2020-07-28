rule Homebrew {
    meta:
        author = "Dylan Katz (@Plazmaz)"
        description = "Homebrew github tokens (Created as part of PasteHunter)"
        reference = "https://github.com/techgaun/github-dorks"
        date = "09/15/19"
    strings:
        $ = "HOMEBREW_GITHUB_API_TOKEN" nocase
    condition:
        all of them
}
