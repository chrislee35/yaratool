import yaratool

if __name__ == "__main__":
    ruletext = """rule DebuggerCheck__API : AntiDebug   DebuggerCheck   {
        meta:
      author="Some dude or dudette" 
     weight =   1
      strings: $ ="IsDebuggerPresent"
                condition: any of them}"""
    yr = yaratool.YaraRule(ruletext)
    print yr.normalize()
    print "Name: %s, Tags: %s, Author: %s" % (yr.name, "&".join(yr.tags), yr.metas['author'])
    print "Strings: "
    for string in yr.strings:
        print "  %s" % (string)
    print "Condition: "
    for condition in yr.conditions:
        print "  %s" % (condition)
    print yr.hash()
