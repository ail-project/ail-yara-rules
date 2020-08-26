du -a ../rules/ | cut -f2 | grep ".yar$" |  parallel "yara {} ./tests/test.txt"
