#!/usr/bin/env python
from yaratool import YaraRule
import getopt, sys

def usage():
    print("Usage: %s -i <in_file> -o <out_file> [-u] [-d]" % sys.argv[0])
    print("-i   specifies an input file to process, default: STDIN")
    print("-o   specifies an output to write to, default: STDOUT")
    print("-u   only output unique signatures (omit if they are duplicated)")
    print("-d   only output duplicate signatures (omit if they are uniq, prints ALL copies of the duplicate)")
    print("The default mode is to print out the first unique signature and omit all duplicates.")

def main():
    try:
        opts, args = getopt.getopt(sys.argv[1:], "i:o:ud")
    except getopt.GetoptError as err:
        # print help information and exit:
        print(err)  # will print something like "option -a not recognized"
        usage()
        sys.exit(2)
    
    in_files = [sys.stdin]
    out_file = sys.stdout
    mode = 'uniq'
    for o, a in opts:
        if o == '-i':
            in_files.remove(sys.stdin)
            in_files.append(open(a, 'r'))
        elif o == '-o':
            out_file = open(a, 'w')
        elif o == '-u':
            mode = 'uniq_only'
        elif o == '-d':
            mode = 'dups_only'
        else:
            assert False, "unhandled option: -%s" % o
    
    rules_cache = {}
    uniq_rules = {}
    for in_file in in_files:
        rulestext = in_file.read()
        rules = YaraRule.split(rulestext)
        for rule in rules:
            name = rule.name
            h = rule.hash()
            if mode == 'uniq':
                # essentially, just print out the first copy and don't do anything for later copies
                if rules_cache.get(h) == None:
                    print(rule.normalize())
                    rules_cache[h] = True
                    
            elif mode == 'uniq_only':
                # if it's in the uniq hash, but seen again, it's no longer uniq, remove it.
                # since it's still in the rules_cache, it won't be added again
                if uniq_rules.get(h):
                    uniq_rules.pop(h)
                elif rules_cache.get(h) == None:
                    uniq_rules[h] = rule
                    rules_cache[h] = True
                    
            elif mode == 'dups_only':
                # if it's in the uniq hash, and seen again, print out the first version and the new version.
                if uniq_rules.get(h):
                    print(uniq_rules[h].normalize())
                    print(rule.normalize())
                    uniq_rules.pop(h)
                elif rules_cache.get(h) == None:
                    uniq_rules[h] = rule
                    rules_cache[h] = True
                else: # it's in the rules cache, but not in the uniq_rules, which means this is the 3 or more copy of the rule
                    print(rule.normalize())

    if mode == 'uniq_only':
        for h in uniq_rules.keys():
            print(uniq_rules[h].normalize())

if __name__ == "__main__":
    main()