# Configuration file
Configuration file should appear in main project directory (next to executable file or one level higher) 
under `config.cfg` name.

Every line that starts with `#` is considered as comment.
Don't use spaces in no comment lines.

On the left side of `=`: questioned (original) site.

On the right side of `=`: spoof site.

Example:
```
# this is a comment
www.want-to-go-to-this-site.com=www.but-going-here.com
www.other-attacked-site.com=www.spoof-site.pl
```