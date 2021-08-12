#!/usr/bin/env python3

import sys
import os
import tempfile
import subprocess
import pdb
import base64
from subprocess import Popen, PIPE
import unittest

def pwmg_path():
    p = os.path.dirname(__file__) + "/../pwmg/pwmg.py"
    assert(os.path.exists(p))
    return p

def load_entries(filename):
    fh = open(filename, "r")
    lines = []
    while True:
        line = fh.readline()
        if not line:
            break
        if line.startswith("#"):
            continue
        lines.append(line.strip())
    fh.close()
    return lines

def run_cmd(cmd, key, password):
    os.environ["PWMG_MASTER_KEY"] = key
    if password:
        os.environ["PWMG_PASSWORD"] = password
    handle = Popen(cmd, stderr=PIPE, stdout=PIPE, stdin=PIPE, text=True)
    output, err = handle.communicate()
    return output, err

class PwmgTest(unittest.TestCase):

    def test1(self):
        key = "ddddaaaa"
        site1 = "site123"
        account1 = "account456"
        password1 = "xxxxxxyyyyyy"

        temp = tempfile.NamedTemporaryFile()
        cmd = ["python3", pwmg_path(), "-f", temp.name]
        cmd.extend(["update", site1, account1])
        _, err = run_cmd(cmd, key, password1)
        assert not err
        cmd = ["python3", pwmg_path(), "-f", temp.name, "show"]
        output, _ = run_cmd(cmd, key, None)
        assert site1 in output and account1 in output and password1 in output
        lines = load_entries(temp.name)
        assert len(lines) == 1
        data = base64.b64decode(lines[0])
        assert len(data) == 256

        site2 = "site 9999"
        account2 = "account9999@yyzz.com"
        password2 = "aabbccddeeff"
        cmd = ["python3", pwmg_path(), "-f", temp.name]
        cmd.extend(["update", site2, account2])
        _, err = run_cmd(cmd, key, password2)
        assert not err
        cmd = ["python3", pwmg_path(), "-f", temp.name, "show"]
        output, _ = run_cmd(cmd, key, None)
        assert site1 in output and account1 in output and password1 in output
        assert site2 in output and account2 in output and password2 in output

        lines = load_entries(temp.name)
        assert len(lines) == 2
        data = base64.b64decode(lines[0])
        assert len(data) == 256
        data = base64.b64decode(lines[1])
        assert len(data) == 256

        # rm
        cmd = ["python3", pwmg_path(), "-f", temp.name]
        cmd.extend(["rm", site1])
        _, err = run_cmd(cmd, key, None)
        assert not err

        cmd = ["python3", pwmg_path(), "-f", temp.name, "show"]
        output, _ = run_cmd(cmd, key, None)
        assert site1 not in output and account1 not in output and \
            password1 not in output
        assert site2 in output and account2 in output and password2 in output

        cmd = ["python3", pwmg_path(), "-f", temp.name, "show", site2]
        output, _ = run_cmd(cmd, key, None)
        assert site2 in output and account2 in output and password2 in output

        # export
        temp2 = tempfile.NamedTemporaryFile()
        cmd = ["python3", pwmg_path(), "-f", temp.name, "export", temp2.name]
        _, err = run_cmd(cmd, key, None)
        assert "Cannot export" in err # file exists

        temp2.file.close()
        os.remove(temp2.name)
        cmd = ["python3", pwmg_path(), "-f", temp.name, "export", temp2.name]
        _, err = run_cmd(cmd, key, None)
        assert not err

        lines = load_entries(temp2.name)
        assert len(lines) == 1 and site2 in lines[0] and \
            account2 in lines[0] and password2 in lines[0]

        password3 = "xxyyzz112233"
        cmd = ["python3", pwmg_path(), "-f", temp.name]
        cmd.extend(["update", site2, account2])
        _, err = run_cmd(cmd, key, password3)
        assert not err

        cmd = ["python3", pwmg_path(), "-f", temp.name, "show", site2]
        output, _ = run_cmd(cmd, key, None)
        assert site2 in output and account2 in output and password3 in output

        # import
        os.environ["PWMG_IMPORT"] = "1"
        cmd = ["python3", pwmg_path(), "-f", temp.name, "import", temp2.name]
        _, err = run_cmd(cmd, key, None)

        cmd = ["python3", pwmg_path(), "-f", temp.name, "show", site2]
        output, _ = run_cmd(cmd, key, None)
        assert site2 in output and account2 in output and password2 in output

        # pw
        os.environ["PWMG_CHANGE_MASTER_KEY"] = "ppqq1122"
        cmd = ["python3", pwmg_path(), "-f", temp.name, "pw"]
        output, _ = run_cmd(cmd, key, None)

        del os.environ["PWMG_CHANGE_MASTER_KEY"]

        output, err = run_cmd(cmd, key, None)
        assert "Failed to decrypt" in err

        cmd = ["python3", pwmg_path(), "-f", temp.name, "show", site2]
        output, _ = run_cmd(cmd, "ppqq1122", None)
        assert site2 in output and account2 in output and password2 in output

if __name__ == "__main__":
    unittest.main()
