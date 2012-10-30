import yaratool
import sys

if __name__ == "__main__":
    count = 0
    duplicates = 0
    drf = yaratool.DuplicateDetector()
    for filename in sys.argv[1:]:
        fh = open(filename, 'r')
        sigrules = fh.read()
        fh.close()
        rules = yaratool.split(sigrules)
        for rule in rules:
            ynhash = rule.hash()
            res = drf.check(rule)
            if res:
                duplicates += 1
                for r in res:
                    print r.normalize()
                    pass
                print rule.normalize()
                print
        count += len(rules)
    print "Count: %d, Duplicates: %d" % (count, duplicates)
