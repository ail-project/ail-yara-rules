# ail-yara-rules

![AIL Project](https://raw.githubusercontent.com/ail-project/ail-logos/master/ail-project-small.png)

A set of YARA rules for the AIL framework to detect leak or information disclosure. This repository can be used by other tools.

# YARA rules

 * [rules](./rules)
     * [code](./rules/code)
       * [vbscript.yar](./rules/code/vbscript.yar)
       * [autoit.yar](./rules/code/autoit.yar)
       * [hex_mz.yar](./rules/code/hex_mz.yar)
       * [powershell.yar](./rules/code/powershell.yar)
     * [keylogger](./rules/keylogger)
       * [ducky_code.yar](./rules/keylogger/ducky_code.yar)
       * [bunny_code.yar](./rules/keylogger/bunny_code.yar)
     * [crypto](./rules/crypto)
       * [certificate.yar](./rules/crypto/certificate.yar)
     * [cloud](./rules/cloud)
       * [aws_cli.yar](./rules/cloud/aws_cli.yar)
       * [sw_bucket.yar](./rules/cloud/sw_bucket.yar)
     * [b64_encoded](./rules/b64_encoded)
       * [b64_xml_doc.yar](./rules/b64_encoded/b64_xml_doc.yar)
       * [b64_docx.yar](./rules/b64_encoded/b64_docx.yar)
       * [b64_rtf.yar](./rules/b64_encoded/b64_rtf.yar)
       * [b64_doc.yar](./rules/b64_encoded/b64_doc.yar)
       * [b64_url.yar](./rules/b64_encoded/b64_url.yar)
       * [b64_gzip.yar](./rules/b64_encoded/b64_gzip.yar)
       * [b64_rar.yar](./rules/b64_encoded/b64_rar.yar)
       * [b64_zip.yar](./rules/b64_encoded/b64_zip.yar)
       * [b64_elf.yar](./rules/b64_encoded/b64_elf.yar)
       * [b64_exe.yar](./rules/b64_encoded/b64_exe.yar)
     * [blacklist](./rules/blacklist)
       * [default.yar](./rules/blacklist/default.yar)
     * [database](./rules/database)
       * [db_connection.yar](./rules/database/db_connection.yar)
       * [db_structure.yar](./rules/database/db_structure.yar)
       * [db_create_user.yar](./rules/database/db_create_user.yar)
     * [obfuscation](./rules/obfuscation)
       * [php_obfuscation.yar](./rules/obfuscation/php_obfuscation.yar)
     * [api-keys](./rules/api-keys)
       * [discord_api.yar](./rules/api-keys/discord_api.yar)
       * [heroku_api.yar](./rules/api-keys/heroku_api.yar)
       * [aws_api.yar](./rules/api-keys/aws_api.yar)
       * [github_api.yar](./rules/api-keys/github_api.yar)
       * [slack_api.yar](./rules/api-keys/slack_api.yar)
       * [google_api.yar](./rules/api-keys/google_api.yar)
       * [twitter_api.yar](./rules/api-keys/twitter_api.yar)
       * [generic_api.yar](./rules/api-keys/generic_api.yar)
       * [github_homebrew.yar](./rules/api-keys/github_homebrew.yar)
       * [shodan_api.yar](./rules/api-keys/shodan_api.yar)
       * [github_jekyll.yar](./rules/api-keys/github_jekyll.yar)
       * [pivotal_token.yar](./rules/api-keys/pivotal_token.yar)
     * [password](./rules/password)
       * [mlab.yar](./rules/password/mlab.yar)
       * [amazon-credentials.yar](./rules/password/amazon-credentials.yar)
       * [salesforce.yar](./rules/password/salesforce.yar)
     * [detection](./rules/detection)
       * [avdetect.yar](./rules/detection/avdetect.yar)
       * [dbgdetect_func.yar](./rules/detection/dbgdetect_func.yar)
       * [dbgdetect_procs.yar](./rules/detection/dbgdetect_procs.yar)
       * [dbgdetect_files.yar](./rules/detection/dbgdetect_files.yar)
       * [sandboxdetect.yar](./rules/detection/sandboxdetect.yar)
       * [vmdetect.yar](./rules/detection/vmdetect.yar)
     * [classified](./rules/classified)
         * [nato.yar](./rules/classified/nato.yar)


# Contributors

- kevthehermit via [PasteHunter](https://github.com/kevthehermit/PasteHunter) for the initial rule set licensed under the GNU General Public License
- [AlienVault-Labs](https://github.com/AlienVault-Labs/AlienVaultLabs/tree/master/malware_rulesets/yara) for some additional rules
- AIL Project contributors

# License

ail-yara-rules is distributed under the AGPL.

# Contribute

It's quite easy. Fork the repository, add or modify existing YARA rule and make a pull request. Please take a look at the directory name to map
the scope of the YARA rule.
