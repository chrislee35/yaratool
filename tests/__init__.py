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
        self.failUnlessEqual("1", yn.meta['weight'])
        self.failUnlessEqual("DataConversion__wide", yn.name)
        self.failUnlessEqual(["IntegerParsing", "DataConversion"], yn.tags)
        self.failUnlessEqual(["$ = \"wtoi\" nocase",
                            "$ = \"wtol\" nocase",
                            "$ = \"wtof\" nocase",
                            "$ = \"wtodb\" nocase"], yn.strings)
        assert_equal(["any of them"], yn.conditions)
        

if __name__ == '__main__':
    unittest.main()
        