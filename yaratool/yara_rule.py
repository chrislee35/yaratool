import re
import hashlib
from pprint import pprint

class YaraRule:
    def __init__(self, ruletext):
        """YaraRule takes in the text of one Yara Rule, rips it apart, normalizes it, and store parts it in various members"""
        ruletext = re.sub('[\r\n]+','\n',ruletext)
        self.original = ruletext
        self.lookup_table = {}
        self.next_replacement = 0
        self.normalized_conditions = []
        
        #commentre = re.compile('\\/\\*.+\\*\\/', flags=re.DOTALL)
        self.comments = []#commentre.findall(ruletext)
        #ruletext = commentre.sub('', ruletext)

        rulere = re.compile(r"rule\s+([\w\_\-]+)(\s*:\s*(\w[\w\s\-\_]+\w))?\s*\{\s*(meta\s*:\s*(.*?))?(strings\s*:\s*(.*?))?\s*condition\s*:\s*(.*?)\s*\}", flags=(re.MULTILINE | re.DOTALL))
        match = rulere.search(ruletext)
        if not match:
            print(ruletext)
            raise Exception("YaraRule cannot parse the rule")
        self.name,iftags,tags,ifmeta,metas,ifstrings,strings,conditions = match.groups()
        #pprint((self.name,iftags,tags,ifmeta,metas,ifstrings,strings,conditions))
        if iftags:
            self.tags = re.split('\s+', tags)
        else:
            self.tags = None

        self.metas = {}
        
        in_multiline_comment = False
        comment = ""
        if ifmeta:
            # another fine patch from dspruell
            mstore = {}
            for item in re.split('\n+', metas):
                if in_multiline_comment:
                    if item.strip().endswith('*/'):
                        comment += item
                        self.comments.append(comment)
                        in_multiline_comment = False
                        comment = ""
                elif item.strip().startswith('/*'):
                    comment = item
                    in_multiline_comment = True
                    if item.strip().endswith('*/'):
                        self.comments.append(comment)
                        in_multiline_comment = False
                        comment = ""
                elif re.search('\w', item):
                    try:
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
                    except ValueError as e:
                        print(item.strip())
                        print(metas)
                        raise(e)
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
                #print(hexmatch)
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
                        elif type(value) == int:
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
        # remove comments from the end of strings (they shouldn't contribute to the hash)
        strings = [ re.sub(r'\s*\/\*.*?\*/$', '', string) for string in self.strings ]
        # only keep the right side value of the string
        normalized_strings = "%".join(sorted([re.sub('^.*?=\s*','',string.strip()) for string in strings]))
        self.normalized_strings = normalized_strings
        normalized_condition = '%'.join([con.strip() for con in self.normalized_conditions])
        strhash = hashlib.md5(normalized_strings.encode('UTF-8')).hexdigest()
        conhash = hashlib.md5(normalized_condition.encode('UTF-8')).hexdigest()
        return "yn01:"+strhash[-16:]+":"+conhash[-10:]
        
    @staticmethod
    def split(rulestext):
        """splits breaks apart a set of yara signatures and returns an array of YaraRule objects
        input: string containing one or more yara signatures
        output: list of YaraRule objects
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