"""
The MIT License

Copyright (c) 2012-2017 Chris Lee (python [at] chrislee.dhs.org)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
"""

import re
import sys
import hashlib

__author__ =  'python@chrislee.dhs.org'
__version__ = "0.0.6"
__url__ = 'https://github.com/chrislee/yaratools'

class YaraRule:
    def __init__(self,ruletext):
        """YaraRule takes in the text of one Yara Rule, rips it apart, normalizes it, and store parts it in various members"""
        ruletext = re.sub('[\r\n]+','\n',ruletext)
        self.original = ruletext
        self.lookup_table = {}
        self.next_replacement = 0

        rulere = re.compile("rule\s+([\w\_\-]+)(\s*:\s*(\w[\w\s\-\_]+\w))?\s*\{\s*(meta:\s*(.*?))?(strings:\s*(.*?))?\s*condition:\s*(.*?)\s*\}", flags=(re.MULTILINE | re.DOTALL))
        match = rulere.search(ruletext)
        if not match:
            raise Exception("YaraRule cannot parse the rule")
        self.name,iftags,tags,ifmeta,metas,ifstrings,strings,conditions = match.groups()
        if iftags:
            self.tags = re.split('\s+', tags)
        else:
            self.tags = None

        self.metas = {}
        if ifmeta:
            # another fine patch from dspruell
            mstore = {}
            for item in re.split('\n+', metas):
                if re.search('\w', item):
                    k,v = re.split('\s*=\s*', item.strip(), maxsplit=1)
                    if re.match('(\+|\-)?\d+', v):
                        v = int(v)
                    elif re.match('(\+|\-)?\d+\.\d+', v):
                        v = float(v)
                    else:
                        v = v.strip('"')
                        if v.lower() in ['true', 'false']:
                          v = v.lower() == 'true'
                    if not k in mstore:
                        mstore[k] = []
                    mstore[k].append(v)
            for k in mstore.keys():
                self.metas[k] = mstore[k][0] if len(mstore[k]) == 1 else mstore[k]
                
        if strings:
            strarr = re.split('\n+', strings)
            self.strings = []
            for item in strarr:
                # clear off beginning and ending spaces, tabs, etc.
                item = item.strip()
                # reformat the spacing around the first equals sign
                item = re.sub('\s*=\s*', ' = ', item, 1)
                # reformat any hex strings to be lower case, space in between each two characters, and the {}
                # e.g., { 01 23 45 67 89 ab cd ef }
                hexmatch = re.search(r' = \{\s*([0-9a-fA-F\s]+?)\s*\}', item)
                if hexmatch:
                    hexstr = re.sub(r'\s', '', hexmatch.groups()[0]).lower()
                    hexstr = " ".join([hexstr[i:i+2] for i in range(0,len(hexstr), 2)])
                    item = re.sub(r' = \{\s*([0-9a-fA-F\s]+?)\s*\}', ' = { '+hexstr+' }', item)
                self.strings.append(item)
        else:
            self.strings = ()
        if conditions:
            self.conditions = [re.sub('^\s+','', item) for item in re.split('\n+', conditions)]
            self.normalized_conditions = [self._normalized_condition(con) for con in self.conditions]
        else:
            self.conditions = ()

    def normalize(self):
        """returns a text version of the rule, but in normalized formatting"""
        text = "rule %s " % (self.name)
        if self.tags:
            text += ": %s " % (" ".join(self.tags))
        text += "{\n"
        if len(self.metas) > 0:
            text += "  meta:\n"
            for key in sorted(self.metas):
                if re.search('\w',key):
                    if type(self.metas[key]) != list:
                        self.metas[key] = [self.metas[key]]
                    for value in self.metas[key]:
                        if type(value) == str:
                            text += "    %s = \"%s\"\n" % (key, value)
                        elif type(value) == bool:
                            text += "    %s = %s\n" % (key, str(value).lower())
                        elif type(value) in [int, long]:
                            text += "    %s = %d\n" % (key, value)
                        elif type(value) == float:
                            text += "    %s = %f\n" % (key, value)
        if len(self.strings) > 0:
            text += "  strings:\n"
            for string in self.strings:
                if re.search('\w',string):
                    text += "    %s\n" % (string)
        if len(self.conditions) > 0:
            text += "  condition:\n"
            for condition in self.conditions:
                if re.search('\w',condition):
                    text += "    %s\n" % (condition)
        text += "}"
        return text
        
    def _replace_var(self,var):
        var = var.group()
        key = var[1:]
        rep = self.lookup_table.get(key)
        if rep:
            return var[0]+rep
        self.lookup_table[key] = str(self.next_replacement)
        self.next_replacement += 1
        return var[0]+self.lookup_table[key]
        
    def _normalized_condition(self,conditions):
        return re.sub(r'[\$\#][\w\d]+',self._replace_var,conditions)
        
    def hash(self):
        """
        returns a normalized yara hash, version 01, the idea is that rules with the same strings and condition should evaluate to the same hash.
        e.g., yn01:042c1fd05933b9b1:4ca58b3314
        """
        normalized_strings = "%".join(sorted([re.sub('^.*?=\s*','',string.strip()) for string in self.strings]))
        self.normalized_strings = normalized_strings
        normalized_condition = '%'.join([con.strip() for con in self.normalized_conditions])
        strhash = hashlib.md5(normalized_strings).hexdigest()
        conhash = hashlib.md5(normalized_condition).hexdigest()
        return "yn01:"+strhash[-16:]+":"+conhash[-10:]

class DuplicateDetector:
    def __init__(self):
        self.rules = {}
    
    def check(self,rule):
        """
        check(rule) takes in a YaraRule object and checks if it's a duplicate
        input: a YaraRule
        output: list of any duplicates (via hash or name) that is know
        
        this updates the database of previously seen rules.  rules are considered the same (duplicate) if the rule hash matches or the name of the rule matches.
        """
        oldrule = self.rules.get(rule.hash())
        oldrule2 = self.rules.get(rule.name)
        result = []
        if oldrule:
            result.append(oldrule)
        else:
            self.rules[rule.hash()] = rule
        if oldrule2:
            result.append(oldrule)
        else:
            self.rules[rule.name] = rule
        return result

def split(rulestext):
    """splits breaks apart a set of yara signatures and returns an array of YaraRule objects
    input: string containing one or more yara signatures
    output: array ("list" in python-speak) of YaraRule objects
    """
    # remove comment lines from signatures
    commentre = re.compile(r"^\s*\/\/.*$",flags=re.MULTILINE)
    rulestext = commentre.sub('', rulestext)
    # extract all the well-formed rules
    # patch by dspruell
    rulere = re.compile("(rule\s+([\w\_\-]+)(\s*:\s*(\w[\w\s]+\w))?\s*\{\s*(meta:\s*(.*?))?(strings:\s*(.*?)\s*)?condition:\s*(.*?)\s*\})", flags=(re.MULTILINE | re.DOTALL))
    # pass each rule to a YaraRule instance for normalization
    rules = [YaraRule(ruletext[0]) for ruletext in rulere.findall(rulestext)]
    return rules
