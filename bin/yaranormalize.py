#!/usr/bin/env python
from yaratool import YaraTool
import sys

if __name__ == "__main__":
    for filename in sys.argv[1:]:
        rulestext = file(filename,'r').read()
        rules = YaraRule.split(rulestext)
        for rule in rules:
            print(rule.normalize())
