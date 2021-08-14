# pwmg
A password management tool

`pwmg` is a standalone python3 script to manage a collection of password
entries. Each entry consists of a site name, an user account name,
and the password. `pwmg` will add a timestamp when it encrypts and stores
the password entry. The encrypted entries are stored in a local file.

A master secrete key is used to encrypt and decrypt password entries.

The algorithm for encryption is XTEA, with 64 rounds of computation.
See https://en.wikipedia.org/wiki/XTEA for more information. Each entry
is padded to 256 bytes, prepended and appended with randomly generated
printable characters. A '\0' is inserted to mark the start and/or end
of the password entry. The entire string is then encrypted, 8-byte
per block, with CBC.

The master secrete key must be more than 8 characters long. It is advised,
but not enforced, to use mixed characters, special characters, and digits.

Perhaps what's interesting about this program is that it is a single file,
uses only standard Python3 libraries, and does not require or download any
additional modules from PyPi repository or any other source. Hence the
user can be assured there is no possible malicious injection of Python
code. You can download just the `pwmg.py` and it is ready to use.

You can install it with the `pip` command

```
# python3 -m pip install pwmg
```

Github link: https://github.com/fredxia/pwmg

## Usage

The default file to store encrypted passwords is `~/.pwmg_db`. There is a
command line option `-f` to use a different file.

To avoid potential leak of passwords in the shell `.history` file master secrete
key or password is only typed in at prompt, not with command line option.

Below is an example to save a password. Notice the master secrete key is
not printed to the terminal (per Python3's `getpass` module).

```text
$ pwmg update 'fred walmart account' testuser2gmail@gmail.com
Secrete key:
Password for fred walmart account:Test&simple2
Site 'fred walmart account' password updated

$ pwmg show
Secrete key:

    --------------------------------------------------------------------------
    | SITE                 | USER NAME           | PASSWORD     | TIMESTAMP  |
    --------------------------------------------------------------------------
    | fred walmart account | testuser2@gmail.com | Test&simple2 | 2021-08-09 |
    --------------------------------------------------------------------------
```

This is what the encrypted file looks like

```text
% cat ~/.pwmg_db
# password file created 2021-08-09
ziNbM2q+FHn7iD4UXWg8tx48DC38eEh+pg+0MxfJogMjsi3H0L3iOC09bISNABMWi4g3UttuMNmF3O7t89/ww7wv7hh1+D98fZ8g/WUkgk3FslRDdJLeGk34BFrP1nIzyQD5adrYRVXtBkFv5pBwBr/lQfWQjsLyP8hMuCJ1DzOFiMAjLRwnIUhitwAqXcQwjo06EHmoi9NllW7W2NAWZQWnMRHHzURt+uBtUvFY9JSAWdLGRDdo2FhfbSeLwfc5ZIbBneMJc0Ye3alP8J9rODwXnoLSHaMY9iLzowHWR72fVP0nZa23ZLsKuZ937EkCX1FJP85IPL+hdSdwS/Y1Yg==
```

You can also remove a site. export passwords to a CSV file, or import passwords
from an exported CSV file. For export and import the delimiter is assumed by
default to be TAB character (can be changed with `-d` option).

Each functionality is a sub command. All sub commands can be listed by the
help option. Without any command line sub command specified the default is
"show" command.

By convention arguments in square brackets are optional in the following "-h"
output.

```text
% pwmg -h
usage: pwmg [-h] [-f <FILENAME>] {show,rm,update,pw,import,export} ...

A password management tool

optional arguments:
  -h, --help            show this help message and exit
  -f <FILENAME>, --file <FILENAME>
                        Password file. Default is ~/.pwmg_db

command:
  {show,rm,update,pw,import,export}
    show                show or search password entries
    update              update or add password entry    
    rm                  remove entry
    pw                  change master secrete key
    import              import from csv file
    export              export to csv file
```

```text
% pwmg update -h
usage: pwmg update [-h] <SITE> <USER NAME>

positional arguments:
  <SITE>       site to delete
  <USER NAME>  user name
```

```text
% pwmg show -h
usage: pwmg show [-h] [<NAME>]

positional arguments:
  <NAME>      site or user name
```

```text
% pwmg rm -h
usage: pwmg rm [-h] <SITE>

positional arguments:
  <SITE>      site to delete
```

```text
% pwmg import -h
usage: pwmg import [-h] [-d <DELIMITER>] <FILE>

positional arguments:
  <FILE>          file to import from
```

```text
% pwmg export -h
usage: pwmg export [-h] [-d <DELIMITER>] <FILE>

positional arguments:
  <FILE>          file to export to

```
