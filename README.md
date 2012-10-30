# Overview

YaraTool was created to normalize yara signatures to format the signatures nicely, detect duplicates, and express a specific signature by hash (similar to how we express malware).  The hashing method in this tool is the same as the Ruby Yara-Normalize module.

# Normalizing a signature

The following snippet takes a signature, normalizes it, prints out the pieces of the rule, and provides the "Yara Normalized" hash.  The YNHash is designed to identify yara signatures.

    import yaratool

    if __name__ == "__main__":
        ruletext = """rule DebuggerCheck__API : AntiDebug   DebuggerCheck   {
        meta:
          author="Some dude or dudette" 
              weight =   1
        strings:
            $ ="IsDebuggerPresent"
        condition:
            any of them
    }"""
        yr = yaratool.YaraRule(ruletext)
        print yr.normalize()
        print "Name: %s, Tags: %s, Author: %s" % (yr.name, "&".join(yr.tags), yr.metas['author'])
        print "Strings: "
        for string in yr.strings:
            print "  %s" % (string)
        print "Condition: "
        for condition in yr.condition:
            print "  %s" % (condition)
        print yr.hash()

Outputs

    rule DebuggerCheck__API : AntiDebug DebuggerCheck {
      meta:
        author = "Some dude or dudette"
        weight = 1
      strings:
        $ = "IsDebuggerPresent"
      condition:
        any of them
    }
    Name: DebuggerCheck__API, Tags: AntiDebug&DebuggerCheck, Author: "Some dude or dudette"
    Strings: 
      $ = "IsDebuggerPresent"
    Condition: 
      any of them
    yn01:d28d649e24c37244:d936fceffe

# Detecting Duplicate Rules

The following code iterates through all the files specified on the command line and counts the number of rules and duplicate rules.  It will display the normalized versions of any duplicate rules.

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

