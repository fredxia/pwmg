#!/usr/bin/env python3
#
# Copyright @2021 by Fred Xia, fredxia2011@gmail.com
# MIT License: https://opensource.org/licenses/MIT
#
# Github: https://github.com/fredxia/pwmg
#
import os
import sys
import datetime
import random
import string
import hashlib
import base64
import struct
import argparse
import getpass
import csv
import tempfile

block_sz = 256

# Pad password entry to 256 bytes with random characters. Padding string
# is randomly split into two pieces. One to prepend and one to append to
# the value. \0 is used to delimit padding and value
def pad_str(value):
    bv = bytes(value, "utf8")
    m = len(bv) % block_sz
    if m == 0:
        return bv
    pad_len = block_sz - m - 2
    p = [ ord(random.choice(string.printable)) for _ in range(pad_len) ]
    split = random.randint(0, pad_len)
    bv2 = bytes(p[:split]) + bytes([0]) + bv
    if split < pad_len:
        bv2 += bytes([0]) + bytes(p[split:])
    assert len(bv2) % block_sz == 0
    return bv2

def unpad_str(value):
    idx = value.find("\x00")
    if idx < 0:
        return value
    idx2 = value.rfind("\x00")
    if idx2 == idx:
        return value[(idx+1):]
    return value[(idx+1):idx2]

def print_err(msg):
    print(msg, file=sys.stderr)

#
# CBC XTEA encryption/decryption
#
delta = 0x9e3779b9
def xtea_encrypt(rounds, v0, v1, key, vector):
    assert len(key) == 4 and len(vector) == 2
    sum = 0
    v0 = v0 ^ vector[0]
    v1 = v1 ^ vector[1]
    for _ in range(rounds):
        v0 += ((((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]))
        v0 &= 0xFFFFFFFF
        sum = sum + delta
        v1 += ((((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum >> 11) & 3]))
        v1 &= 0xFFFFFFFF
    return v0, v1

def xtea_decrypt(rounds, v0, v1, key, vector):
    assert len(key) == 4 and len(vector) == 2
    sum = delta * rounds
    for _ in range(rounds):
        v1 -= ((((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum >> 11) & 3]))
        v1 &= 0xFFFFFFFF
        sum -= delta
        v0 -= ((((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]))
        v0 &= 0xFFFFFFFF
    return v0 ^ vector[0] , v1 ^ vector[1]

def xtea_encipher(rounds, source, key):
    assert rounds > 39 and isinstance(source, str) and \
        isinstance(key, str)
    source = pad_str(source)
    key = bytes(key, "utf8")
    ekeys = struct.unpack("<IIII", hashlib.md5(key).digest())
    vector = [ekeys[0], ekeys[1]] # use first 8 bytes as init vector
    result = bytes(0)
    idx = 0
    while idx < len(source):
        v0, v1 = struct.unpack("<II", source[idx:(idx+8)])
        ev0, ev1 = xtea_encrypt(rounds, v0, v1, ekeys, vector)
        result += struct.pack("<I", ev0)
        result += struct.pack("<I", ev1)
        vector[0] = ev0
        vector[1] = ev1
        idx += 8
    return base64.b64encode(result).decode("utf8")

def xtea_decipher(rounds, source, key):
    assert rounds > 39 and isinstance(source, str) and \
        isinstance(key, str)
    source = base64.b64decode(source)
    assert len(source) % 8 == 0
    key = bytes(key, "utf8")
    ekeys = struct.unpack("<IIII", hashlib.md5(key).digest())
    vector = [ekeys[0], ekeys[1]]
    idx = 0
    result = bytes(0)
    while idx < len(source):
        v0, v1 = struct.unpack("<II", source[idx:(idx+8)])
        dv0, dv1 = xtea_decrypt(rounds, v0, v1, ekeys, vector)
        result += struct.pack("<I", dv0)
        result += struct.pack("<I", dv1)
        vector = [v0, v1]
        idx += 8
    try:
        return unpad_str(result.decode("utf8"))
    except:
        return None

xtea_rounds = 64 # rounds of XTEA encrypt/decrypt
min_key_len = 8 # minimal master key length

def default_password_file():
    return "%s/.pwmg_db" % os.environ["HOME"]

def first_line():
    return "# version 0.0.5 file created %s" % str(datetime.date.today())

def load_passwords(filename, key):
    fh = open(filename, "r")
    if not fh:
        print_err("Cannot open password file %s" % filename)
        exit(1)
    line_num = 0
    result = {}
    failed = 0
    while True:
        line = fh.readline().strip()
        if not line:
            break
        if line.startswith("# "):
            continue
        dv = xtea_decipher(xtea_rounds, line, key)
        if not dv:
            print_err("Failed to decrypt line %d" % line_num)
            failed += 1
        else:
            items = dv.split("\t")
            # site, name, pw, timestamp
            assert len(items) == 4
            if items[0] in result:
                print_err("Double entry detected: %s" % items[0])
            result[items[0]] = items
        line_num += 1
    fh.close()
    if line_num > 0 and failed == line_num:
        print_err("Failed to load %s entries" % line_num)
        exit(1)
    return result

def save_passwords(filename, pws, key):
    temp = tempfile.NamedTemporaryFile(mode="w", encoding="utf8", delete=False)
    if not temp:
        print_err("Cannot open temp password file")
        exit(1)
    print(first_line(), file=temp.file)
    for site in pws:
        row = pws[site]
        assert len(row) == 4
        v = "\t".join(row)
        dv = xtea_encipher(xtea_rounds, v, key)
        assert(dv)
        print(dv, file=temp.file)
    temp.file.close()
    if os.path.exists(filename):
        bk = filename + ".back"
        if os.path.exists(bk):
            os.remove(bk)
        os.rename(filename, bk)
    os.rename(temp.name, filename)
    return len(pws)

def pretty_print(pws):
    titles = ["SITE", "USER NAME", "PASSWORD", "TIMESTAMP"]
    col_widths = [ len(x) for x in titles ]
    for k, row in pws.items():
        for i, v in enumerate(row):
            if len(v) > col_widths[i]:
                col_widths[i] = len(v)
    format_str = "    | {:<%d} | {:<%d} | {:<%d} | {:<%d} |" % (
        col_widths[0], col_widths[1], col_widths[2], col_widths[3])
    print_line = lambda : print("    " + "-" * (sum(col_widths) + 13))
    print("")
    print_line()
    print(format_str.format(titles[0], titles[1], titles[2], titles[3]))
    print_line()
    for k in sorted(pws):
        row = pws[k]
        print(format_str.format(row[0], row[1], row[2], row[3]))
    print_line()

def get_input(prompt):
    if not sys.stdin.isatty():
        k = "PWMG_CHANGE_MASTER_KEY" if "change" in prompt else \
            "PWMG_MASTER_KEY" if "key" in prompt else "PWMG_PASSWORD"
        return os.environ.get(k, "")
    if prompt == "master-key":
        return getpass.getpass("Secrete key:")
    elif prompt == "confirm-master-key" or \
         prompt == "confirm-change-master-key":
        return getpass.getpass("Confirm secrete key:")
    elif prompt == "change-master-key":
        return getpass.getpass("New secrete key:")
    elif prompt == "password":
        return input("Site password:")
    assert False, "Invalid prompt or missing environment setup"

def init_parser():
    parser = argparse.ArgumentParser(description="A password management tool")
    parser.add_argument(
        "-f", "--file", metavar="<FILENAME>", type=str,
        help="Password file. Default is ~/.pwmg_db"
    )
    subs = parser.add_subparsers(title="command", dest="cmd")
    show_cmd = subs.add_parser("show", help="show or search password entries")
    show_cmd.add_argument(
        "name", metavar="<NAME>", help="site or user name", nargs="?"
    )
    update_cmd = subs.add_parser("update", help="update or add password entry")
    update_cmd.add_argument("site", metavar="<SITE>", help="site to delete")
    update_cmd.add_argument("user", metavar="<USER NAME>", help="user name")
    rm_cmd = subs.add_parser("rm", help="remove entry")
    rm_cmd.add_argument("site", metavar="<SITE>", help="site to delete")
    pw_cmd = subs.add_parser("pw", help="change master secrete key")
    import_cmd = subs.add_parser("import", help="import from csv file")
    import_cmd.add_argument(
        "-d", metavar="<DELIMITER>", default="\t",
        help="column delimiter, default is tab"
    )
    import_cmd.add_argument(
        "source", metavar="<FILE>", help="file to import from"
    )
    export_cmd = subs.add_parser("export", help="export to csv file")
    export_cmd.add_argument(
        "-d", metavar="<DELIMITER>", default="\t",
        help="column delimiter, default is tab"
    )
    export_cmd.add_argument(
        "dest", metavar="<FILE>", help="file to export to"
    )
    return parser

def show_cmd(args):
    pws = load_passwords(args.file, args.pw)
    if not args.name:
        result = pws
    else:
        result = {}
        for k, v in pws.items():
            if args.name in k:
                result[args.name] = v
            elif args.name in v[1] or args.name in v[3]:
                result[args.name] = v
    if not result:
        print("No match found")
        return
    pretty_print(result)

def rm_cmd(args):
    pws = load_passwords(args.file, args.pw)
    if not pws:
        print("No entries found")
        return
    if args.site in pws:
        del pws[args.site]
        save_passwords(args.file, pws, args.pw)
        print("Site '%s' removed" % args.site)
    else:
        print("No match found")

def update_cmd(args):
    pws = load_passwords(args.file, args.pw) \
        if os.path.exists(args.file) else {}
    if not pws:
        pw2 = get_input("confirm-master-key")
        if pw2 != args.pw:
            print_err("Passwords do not match")
            exit(1)
    pw = get_input("password")
    pws[args.site] = (args.site, args.user, pw, str(datetime.date.today()))
    save_passwords(args.file, pws, args.pw)
    print("Site '%s' password updated" % args.site)

def pw_cmd(args):
    pws = load_passwords(args.file, args.pw)
    new_pw = get_input("change-master-key")
    if len(new_pw) < min_key_len:
        print_err("Secrete key length must be at least %d" % min_key_len)
        exit(1)
    pw2 = get_input("confirm-change-master-key")
    if new_pw != pw2:
        print_err("Passwords do not match")
        exit(1)
    save_passwords(args.file, pws, new_pw)

def import_cmd(args):
    overwrite = False
    if os.path.exists(args.file):
        pws = load_passwords(args.file, args.pw)
    else:
        pws = {}
    if pws:
        if "PWMG_IMPORT" in os.environ:
            overwrite = os.environ["PWMG_IMPORT"] == "1"
        else:
            c = input("Password file exists. " + \
                      "Merge, overwrite or cancel(m/o/c)? ")
            if c == "c":
                print("Import cancelled")
                exit(0)
            if c == "o":
                y = input("Confirm overwrite existing password file (y/n)? ")
                if y != "y":
                    exit(0)
                overwrite = True
    if not os.path.exists(args.source):
        print_err("Cannot import. File %s does not exist" % args.source)
        exit(1)
    fh = open(args.source, "r")
    if not fh:
        print_err("Open file %s failed" % args.source)
        exit(1)
    csv_reader = csv.reader(fh, delimiter=args.d)
    line_num = 0
    new_pws = {}
    today = str(datetime.date.today())
    for row in csv_reader:
        if len(row) != 3 and len(row) != 4:
            print_err("Parse error on line %d" % line_num)
        else:
            new_pws[row[0]] = (row[0], row[1], row[2],
                               row[3] if len(row) == 4 else today)
    print(new_pws)
    if overwrite:
        for k in new_pws:
            pws[k] = new_pws[k]
    else:
        for k in pws:
            new_pws[k] = pws[k]
        pws = new_pws
    save_passwords(args.file, pws, args.pw)
    print("Imported to %s. Total number of entries %s" % (args.file, len(pws)))

def export_cmd(args):
    if os.path.exists(args.dest):
        print_err("Cannot export. File %s exists" % args.dest)
        exit(1)
    fh = open(args.dest, "w")
    if not fh:
        print_err("Open file %s failed" % args.dest)
    pws = load_passwords(args.file, args.pw)
    if not pws:
        print("Nothing to export")
        exit(1)
    if args.d != "\t":
        csv_writer = csv.writer(fh, delimiter=args.d, quotechar='"')
    else:
        csv_writer = csv.writer(fh, delimiter="\t")
    for _, v in pws.items():
        csv_writer.writerow(v)
    fh.close()
    print("Exported to file %s" % args.dest)

def main():
    parser = init_parser()
    args = parser.parse_args()
    if not args.cmd:
        args.cmd = "show"
        args.name = None
    if not args.file:
        args.file = default_password_file()
    if args.cmd in ["show", "rm", "export", "pw"]:
        if not os.path.exists(args.file):
            print_err("Password file does not exist")
            exit(1)
    pw = get_input("master-key")
    if len(pw) < min_key_len:
        print_err("Secrete key length must be at least %d" % min_key_len)
        exit(1)
    args.pw = pw
    if args.cmd == "show":
        show_cmd(args)
    elif args.cmd == "rm":
        rm_cmd(args)
    elif args.cmd == "update":
        update_cmd(args)
    elif args.cmd == "pw":
        pw_cmd(args)
    elif args.cmd == "import":
        import_cmd(args)
    elif args.cmd == "export":
        export_cmd(args)
    else:
        print_err("Invalid command")

if __name__ == "__main__":
    main()
