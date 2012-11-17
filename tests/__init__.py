import yaratool
import unittest

class TestYaraTool(unittest.TestCase):
    def testMalformedRule(self):
        ruletext = "rule{}"
        try:
            yn = yaratool.YaraRule(ruletext)
        except Exception:
            pass
        else:
            self.fail("Parsing the malformed rule should have raised an exception")
    
    def testRuleNormalization(self):
        ruletext = r"""rule dbgdetect_procs : dbgdetect
{
meta:
author = "AlienVault Labs"
type = "info"
severity = 1
description = "Debugger detection tricks"

strings:
$proc1 = "wireshark" nocase ascii wide
$proc2 = "filemon" nocase ascii wide
$proc3 = "procexp" nocase ascii wide
$proc4 = "procmon" nocase ascii wide
$proc5 = "regmon" nocase ascii wide
$proc6 = "idag" nocase ascii wide
$proc7 = "immunitydebugger" nocase ascii wide
$proc8 = "ollydbg" nocase ascii wide
$proc9 = "petools" nocase ascii wide
$test1 = "A\x0aB\x0aC\x0aD" nocase

condition:
2 of them
}"""
        yn = yaratool.YaraRule(ruletext)
        self.failUnlessEqual("dbgdetect_procs",yn.name)
        self.failUnlessEqual("\"AlienVault Labs\"",yn.metas['author'])
        self.failUnlessEqual(["$proc1 = \"wireshark\" nocase ascii wide",
                "$proc2 = \"filemon\" nocase ascii wide",
                "$proc3 = \"procexp\" nocase ascii wide",
                "$proc4 = \"procmon\" nocase ascii wide",
                "$proc5 = \"regmon\" nocase ascii wide",
                "$proc6 = \"idag\" nocase ascii wide",
                "$proc7 = \"immunitydebugger\" nocase ascii wide",
                "$proc8 = \"ollydbg\" nocase ascii wide",
                "$proc9 = \"petools\" nocase ascii wide",
                "$test1 = \"A\\x0aB\\x0aC\\x0aD\" nocase",
                ], yn.strings)
        self.failUnlessEqual(["2 of them"],yn.conditions)
        self.failUnlessEqual(r"""rule dbgdetect_procs : dbgdetect {
  meta:
    author = "AlienVault Labs"
    description = "Debugger detection tricks"
    severity = 1
    type = "info"
  strings:
    $proc1 = "wireshark" nocase ascii wide
    $proc2 = "filemon" nocase ascii wide
    $proc3 = "procexp" nocase ascii wide
    $proc4 = "procmon" nocase ascii wide
    $proc5 = "regmon" nocase ascii wide
    $proc6 = "idag" nocase ascii wide
    $proc7 = "immunitydebugger" nocase ascii wide
    $proc8 = "ollydbg" nocase ascii wide
    $proc9 = "petools" nocase ascii wide
    $test1 = "A\x0aB\x0aC\x0aD" nocase
  condition:
    2 of them
}""", yn.normalize())
        self.failUnlessEqual("yn01:fc93b999aa0d00b1:5cf26fa932",yn.hash())
        yn.tags = ['tag1', 'tag2', 'tag3']
        self.failUnlessEqual(r"""rule dbgdetect_procs : tag1 tag2 tag3 {
  meta:
    author = "AlienVault Labs"
    description = "Debugger detection tricks"
    severity = 1
    type = "info"
  strings:
    $proc1 = "wireshark" nocase ascii wide
    $proc2 = "filemon" nocase ascii wide
    $proc3 = "procexp" nocase ascii wide
    $proc4 = "procmon" nocase ascii wide
    $proc5 = "regmon" nocase ascii wide
    $proc6 = "idag" nocase ascii wide
    $proc7 = "immunitydebugger" nocase ascii wide
    $proc8 = "ollydbg" nocase ascii wide
    $proc9 = "petools" nocase ascii wide
    $test1 = "A\x0aB\x0aC\x0aD" nocase
  condition:
    2 of them
}""", yn.normalize())
        self.failUnlessEqual("yn01:fc93b999aa0d00b1:5cf26fa932",yn.hash())
    
    def testRuleNormalization2(self):
        ruletext = """rule DataConversion__wide : IntegerParsing DataConversion {
meta:
weight = 1
strings:
$ = "wtoi" nocase
$ = "wtol" nocase
$ = "wtof" nocase
$ = "wtodb" nocase
condition:
any of them
}"""
        yn = yaratool.YaraRule(ruletext)
        self.failUnlessEqual("yn01:a5fd8576f2da34e2:d936fceffe", yn.hash())
        self.failUnlessEqual("1", yn.metas['weight'])
        self.failUnlessEqual("DataConversion__wide", yn.name)
        self.failUnlessEqual(["IntegerParsing", "DataConversion"], yn.tags)
        self.failUnlessEqual(["$ = \"wtoi\" nocase",
                            "$ = \"wtol\" nocase",
                            "$ = \"wtof\" nocase",
                            "$ = \"wtodb\" nocase"], yn.strings)
        self.failUnlessEqual(["any of them"], yn.conditions)
    
    def testRuleNormalizationWithoutStrings(self):
        ruletext = """rule encryption_Camellia: encryption camellia summary
{
meta:
description = "Camellia encryption algorithm"
domain = "encryption"
algorithm = "Camellia"
reference = "RFC 3713, http://www.ietf.org/rfc/rfc3713.txt"
rule_author = "Andreas Schuster"
weight = 192
condition:
(
encryption_Camellia_sigma_be
or encryption_Camellia_sigma_le
or encryption_Camellia_splitsigma_be
or encryption_Camellia_splitsigma_le
) and (
encryption_Camellia_combinedsbox1
or (encryption_Camellia_sbox1 and encryption_Camellia_tables)
)
}"""
        yn = yaratool.YaraRule(ruletext)
        self.failUnlessEqual("yn01:e9800998ecf8427e:e4ce92c847", yn.hash())
        self.failUnlessEqual("encryption_Camellia", yn.name)
        self.failUnlessEqual(["encryption","camellia","summary"], yn.tags)
        self.failUnlessEqual("\"Camellia encryption algorithm\"", yn.metas['description'])
        self.failUnlessEqual("192", yn.metas['weight'])
        self.failUnlessEqual(["(","encryption_Camellia_sigma_be","or encryption_Camellia_sigma_le",
                        "or encryption_Camellia_splitsigma_be", "or encryption_Camellia_splitsigma_le",
                        ") and (", "encryption_Camellia_combinedsbox1",
                        "or (encryption_Camellia_sbox1 and encryption_Camellia_tables)",
                        ")"], yn.conditions)

if __name__ == '__main__':
    unittest.main()