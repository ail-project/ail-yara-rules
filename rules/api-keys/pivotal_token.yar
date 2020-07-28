rule PivotalToken {
    meta:
        author = "Dylan Katz (@Plazmaz)"
        description = "PivotalTracker token (Created as part of PasteHunter)"
        reference = "https://github.com/techgaun/github-dorks"
        date = "09/15/19"
    strings:
        $ = "PT_TOKEN"
    condition:
        any of them
}
