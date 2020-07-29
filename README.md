# ail-yara-rules

![AIL Project](https://raw.githubusercontent.com/ail-project/ail-logos/master/ail-project-small.png)

A set of YARA rules for the AIL framework to detect leak or information disclosure. This repository can be used by other tools.

# YARA rules

 * [code](./code)
   * [vbscript.yar](./code/vbscript.yar)
   * [autoit.yar](./code/autoit.yar)
   * [hex_mz.yar](./code/hex_mz.yar)
   * [powershell.yar](./code/powershell.yar)
 * [keylogger](./keylogger)
   * [ducky_code.yar](./keylogger/ducky_code.yar)
   * [bunny_code.yar](./keylogger/bunny_code.yar)
 * [crypto](./crypto)
   * [certificate.yar](./crypto/certificate.yar)
 * [cloud](./cloud)
   * [aws_cli.yar](./cloud/aws_cli.yar)
   * [sw_bucket.yar](./cloud/sw_bucket.yar)
 * [b64_encoded](./b64_encoded)
   * [b64_xml_doc.yar](./b64_encoded/b64_xml_doc.yar)
   * [b64_docx.yar](./b64_encoded/b64_docx.yar)
   * [b64_rtf.yar](./b64_encoded/b64_rtf.yar)
   * [b64_doc.yar](./b64_encoded/b64_doc.yar)
   * [b64_url.yar](./b64_encoded/b64_url.yar)
   * [b64_gzip.yar](./b64_encoded/b64_gzip.yar)
   * [b64_rar.yar](./b64_encoded/b64_rar.yar)
   * [b64_zip.yar](./b64_encoded/b64_zip.yar)
   * [b64_elf.yar](./b64_encoded/b64_elf.yar)
   * [b64_exe.yar](./b64_encoded/b64_exe.yar)
 * [blacklist](./blacklist)
   * [default.yar](./blacklist/default.yar)
 * [database](./database)
   * [db_connection.yar](./database/db_connection.yar)
   * [db_structure.yar](./database/db_structure.yar)
   * [db_create_user.yar](./database/db_create_user.yar)
 * [obfuscation](./obfuscation)
   * [php_obfuscation.yar](./obfuscation/php_obfuscation.yar)
 * [api-keys](./api-keys)
   * [discord_api.yar](./api-keys/discord_api.yar)
   * [heroku_api.yar](./api-keys/heroku_api.yar)
   * [aws_api.yar](./api-keys/aws_api.yar)
   * [github_api.yar](./api-keys/github_api.yar)
   * [slack_api.yar](./api-keys/slack_api.yar)
   * [google_api.yar](./api-keys/google_api.yar)
   * [twitter_api.yar](./api-keys/twitter_api.yar)
   * [generic_api.yar](./api-keys/generic_api.yar)
   * [github_homebrew.yar](./api-keys/github_homebrew.yar)
   * [shodan_api.yar](./api-keys/shodan_api.yar)
   * [github_jekyll.yar](./api-keys/github_jekyll.yar)
   * [pivotal_token.yar](./api-keys/pivotal_token.yar)
 * [password](./password)
     * [mlab.yar](./password/mlab.yar)
     * [amazon-credentials.yar](./password/amazon-credentials.yar)
     * [salesforce.yar](./password/salesforce.yar)

# Contributors

- kevthehermit via [PasteHunter](https://github.com/kevthehermit/PasteHunter) for the initial rule set licensed under the GNU General Public License

# License

ail-yara-rules is distributed under the AGPL.

# Contribute

It's quite easy. Fork the repository, add or modify existing YARA rule and make a pull request. Please take a look at the directory name to map
the scope of the YARA rule.
