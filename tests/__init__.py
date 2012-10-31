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
        ruletext = """rule newIE0daymshtmlExec
        {
        meta:
        		author = "redacted @ gmail.com"
        		 ref ="http://blog.vulnhunt.com/index.php/2012/09/17/ie-execcommand-fuction-use-after-free-vulnerability-0day_en/"
        		  description = "Internet Explorer CMshtmlEd::Exec() 0day"
        		   cve ="CVE-2012-XXXX"
        		  version= "1"
        		 impact =4
        		hide=false
        	  strings:
        		$mshtmlExec_1 =/document.execCommand(['"]selectAll['"])/ nocase fullword
        		 $mshtmlExec_2= /YMjf\u0c08\u0c0cKDogjsiIejengNEkoPDjfiJDIWUAzdfghjAAuUFGGBSIPPPUDFJKSOQJGH/ nocase fullword
        		  $mshtmlExec_3=/<body on(load|select)=['"]w*?();['"] on(load|select)=['"]w*?()['"]/ nocase
        		   $mshtmlExec_4 =/var w{1,} = new Array()/ nocase
        		    $mshtmlExec_5  = /window.document.createElement(['"]img['"])/ nocase
        		   $mshtmlExec_6 =  /w{1,}[0][['"]src['"]] = ['"]w{1,}['"]/ nocase
        		  $mshtmlExec_7  =  /<iframe src=['"].*?['"]/ nocase
        	condition: ($mshtmlExec_1 and $mshtmlExec_2 and $mshtmlExec_3) or ($mshtmlExec_4 and $mshtmlExec_5 and ($mshtmlExec_6 or $mshtmlExec_7))
        }
        """
        yn = yaratool.YaraRule(ruletext)
        self.failUnlessEqual("newIE0daymshtmlExec",yn.name)
        self.failUnlessEqual("\"redacted @ gmail.com\"",yn.metas['author'])
        self.failUnlessEqual(["$mshtmlExec_1 = /document.execCommand(['\"]selectAll['\"])/ nocase fullword",
                            "$mshtmlExec_2 = /YMjf\\u0c08\\u0c0cKDogjsiIejengNEkoPDjfiJDIWUAzdfghjAAuUFGGBSIPPPUDFJKSOQJGH/ nocase fullword",
                            "$mshtmlExec_3 = /<body on(load|select)=['\"]w*?();['\"] on(load|select)=['\"]w*?()['\"]/ nocase",
                            "$mshtmlExec_4 = /var w{1,} = new Array()/ nocase",
                            "$mshtmlExec_5 = /window.document.createElement(['\"]img['\"])/ nocase",
                            "$mshtmlExec_6 = /w{1,}[0][['\"]src['\"]] = ['\"]w{1,}['\"]/ nocase",
                            "$mshtmlExec_7 = /<iframe src=['\"].*?['\"]/ nocase"], yn.strings)
        self.failUnlessEqual(["($mshtmlExec_1 and $mshtmlExec_2 and $mshtmlExec_3) or ($mshtmlExec_4 and $mshtmlExec_5 and ($mshtmlExec_6 or $mshtmlExec_7))"],yn.conditions)
        self.failUnlessEqual("""rule newIE0daymshtmlExec {
  meta:
    author = "redacted @ gmail.com"
    cve = "CVE-2012-XXXX"
    description = "Internet Explorer CMshtmlEd::Exec() 0day"
    hide = false
    impact = 4
    ref = "http://blog.vulnhunt.com/index.php/2012/09/17/ie-execcommand-fuction-use-after-free-vulnerability-0day_en/"
    version = "1"
  strings:
    $mshtmlExec_1 = /document.execCommand(['"]selectAll['"])/ nocase fullword
    $mshtmlExec_2 = /YMjf\u0c08\u0c0cKDogjsiIejengNEkoPDjfiJDIWUAzdfghjAAuUFGGBSIPPPUDFJKSOQJGH/ nocase fullword
    $mshtmlExec_3 = /<body on(load|select)=['"]w*?();['"] on(load|select)=['"]w*?()['"]/ nocase
    $mshtmlExec_4 = /var w{1,} = new Array()/ nocase
    $mshtmlExec_5 = /window.document.createElement(['"]img['"])/ nocase
    $mshtmlExec_6 = /w{1,}[0][['"]src['"]] = ['"]w{1,}['"]/ nocase
    $mshtmlExec_7 = /<iframe src=['"].*?['"]/ nocase
  condition:
    ($mshtmlExec_1 and $mshtmlExec_2 and $mshtmlExec_3) or ($mshtmlExec_4 and $mshtmlExec_5 and ($mshtmlExec_6 or $mshtmlExec_7))
}""", yn.normalize())
        self.failUnlessEqual("yn01:66dd624d64a79f17:ecf1725295",yn.hash())
        yn.tags = ['tag1', 'tag2', 'tag3']
        self.failUnlessEqual("""rule newIE0daymshtmlExec : tag1 tag2 tag3 {
  meta:
    author = "redacted @ gmail.com"
    cve = "CVE-2012-XXXX"
    description = "Internet Explorer CMshtmlEd::Exec() 0day"
    hide = false
    impact = 4
    ref = "http://blog.vulnhunt.com/index.php/2012/09/17/ie-execcommand-fuction-use-after-free-vulnerability-0day_en/"
    version = "1"
  strings:
    $mshtmlExec_1 = /document.execCommand(['"]selectAll['"])/ nocase fullword
    $mshtmlExec_2 = /YMjf\u0c08\u0c0cKDogjsiIejengNEkoPDjfiJDIWUAzdfghjAAuUFGGBSIPPPUDFJKSOQJGH/ nocase fullword
    $mshtmlExec_3 = /<body on(load|select)=['"]w*?();['"] on(load|select)=['"]w*?()['"]/ nocase
    $mshtmlExec_4 = /var w{1,} = new Array()/ nocase
    $mshtmlExec_5 = /window.document.createElement(['"]img['"])/ nocase
    $mshtmlExec_6 = /w{1,}[0][['"]src['"]] = ['"]w{1,}['"]/ nocase
    $mshtmlExec_7 = /<iframe src=['"].*?['"]/ nocase
  condition:
    ($mshtmlExec_1 and $mshtmlExec_2 and $mshtmlExec_3) or ($mshtmlExec_4 and $mshtmlExec_5 and ($mshtmlExec_6 or $mshtmlExec_7))
}""", yn.normalize())
        self.failUnlessEqual("yn01:66dd624d64a79f17:ecf1725295",yn.hash())
    
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
        