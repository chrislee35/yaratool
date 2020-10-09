#!/usr/bin/env python
from yaratool import YaraRule
import getopt, sys

def usage():
    print("Usage: %s -i <in_file> -o <out_file> [-u] [-d]" % sys.argv[0])
    print("-i   specifies an input file to process, default: STDIN")
    print("-o   specifies an output to write to, default: STDOUT")
    print("-h   include the yara hash as part of the output")
    print("-H   only print the yara hash for each rule")

def main():
    try:
        opts, args = getopt.getopt(sys.argv[1:], "i:o:hH")
    except getopt.GetoptError as err:
        # print help information and exit:
        print(err)  # will print something like "option -a not recognized"
        usage()
        sys.exit(2)
        
    in_files = [sys.stdin]
    out_file = sys.stdout
    mode = 'norm'
    for o, a in opts:
        if o == '-i':
            in_files.remove(sys.stdin)
            in_files.append(open(a, 'r'))
        elif o == '-o':
            out_file = open(a, 'w')
        elif o == '-h':
            mode = 'normhash'
        elif o == '-H':
            mode = 'hash'
        else:
            assert False, "unhandled option: -%s" % o
    
    for in_file in in_files:
        rulestext = in_file.read()
        rules = YaraRule.split(rulestext)
        for rule in rules:
            name = rule.name
            h = rule.hash()
            if mode == 'norm':
                print(rule.normalize())
            elif mode == 'normhash':
                norm = rule.normalize().replace('meta:', 'meta:\n    yarahash = "%s"' % h)
                print(norm)
            elif mode == 'hash':
                print('%s: %s' % (rule.name, h))
                
if __name__ == "__main__":
    main()
