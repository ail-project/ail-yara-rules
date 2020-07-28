rule MLab {
    meta:
        author = "Dylan Katz (@Plazmaz)"
        description = "MLab mongodb credentials (Created as part of PasteHunter)"
        reference = "https://github.com/techgaun/github-dorks"
        date = "09/15/19"
    strings:
        $ = ".mlab.com" nocase
        $ = "password" nocase
    condition:
        all of them
}
