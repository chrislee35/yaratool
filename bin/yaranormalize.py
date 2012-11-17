#!/usr/bin/env python
import yaratool
import sys

if __name__ == "__main__":
    for filename in sys.argv[1:]:
        rulestext = file(filename,'r').read()
        rules = yaratool.split(rulestext)
        for rule in rules:
            print rule.normalize()
