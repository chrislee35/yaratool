class DuplicateDetector:
    def __init__(self):
        self.rules = {}
    
    def check(self, rule):
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

