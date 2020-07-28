rule AmazonCredentials {
    meta:
        author = "Dylan Katz (@Plazmaz)"
        description = "Generic AWS credentials for RDS or EC2 (Created as part of PasteHunter)"
        reference = "https://github.com/techgaun/github-dorks"
        date = "09/15/19"
    strings:
        $rds = "rds.amazonaws.com" nocase
        $ec2 = "ec2.amazonaws.com" nocase
        $pass = "password" nocase
    condition:
        $pass and ($rds or $ec2)
}
