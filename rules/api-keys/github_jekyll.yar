rule JekyllGitHub {
    meta:
        author = "Dylan Katz (@Plazmaz)"
        description = "Jekyll Token for GitHub (Created as part of PasteHunter)"
        reference = "https://github.com/techgaun/github-dorks"
        date = "09/15/19"
    strings:
        $ = "JEKYLL_GITHUB_TOKEN" nocase
    condition:
        all of them
}
