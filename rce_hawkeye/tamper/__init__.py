"""
Tamper插件模块
借鉴sqlmap的tamper设计，实现Payload变形和WAF绕过
"""

import base64
import random
import re
import string
import urllib.parse
from typing import Callable, Dict, List, Optional, Any


def space2comment(payload: str, **kwargs) -> str:
    """空格替换为注释"""
    return payload.replace(" ", "/**/")


def space2plus(payload: str, **kwargs) -> str:
    """空格替换为加号"""
    return payload.replace(" ", "+")


def space2tab(payload: str, **kwargs) -> str:
    """空格替换为Tab"""
    return payload.replace(" ", "\t")


def space2newline(payload: str, **kwargs) -> str:
    """空格替换为换行符"""
    return payload.replace(" ", "%0a")


def space2ifs(payload: str, **kwargs) -> str:
    """空格替换为IFS变量"""
    return payload.replace(" ", "${IFS}")


def randomcase(payload: str, **kwargs) -> str:
    """随机大小写变换"""
    result = ""
    for char in payload:
        if char.isalpha():
            result += char.upper() if random.random() < 0.5 else char.lower()
        else:
            result += char
    return result


def lowercase(payload: str, **kwargs) -> str:
    """转换为小写"""
    return payload.lower()


def uppercase(payload: str, **kwargs) -> str:
    """转换为大写"""
    return payload.upper()


def base64encode(payload: str, **kwargs) -> str:
    """Base64编码"""
    return base64.b64encode(payload.encode()).decode()


def urlencode(payload: str, **kwargs) -> str:
    """URL编码"""
    return urllib.parse.quote(payload, safe='')


def doubleurlencode(payload: str, **kwargs) -> str:
    """双重URL编码"""
    return urllib.parse.quote(urllib.parse.quote(payload, safe=''), safe='')


def charencode(payload: str, **kwargs) -> str:
    """字符URL编码"""
    result = ""
    for char in payload:
        if char.isalnum():
            result += char
        else:
            result += f"%{ord(char):02x}"
    return result


def chardoubleencode(payload: str, **kwargs) -> str:
    """字符双重URL编码"""
    result = ""
    for char in payload:
        if char.isalnum():
            result += char
        else:
            encoded = f"%{ord(char):02x}"
            result += f"%{ord('%'):02x}{encoded[1:3]}%{ord(encoded[3]):02x}"
    return result


def hexencode(payload: str, **kwargs) -> str:
    """十六进制编码"""
    return ''.join(f'\\x{ord(c):02x}' for c in payload)


def unicodeencode(payload: str, **kwargs) -> str:
    """Unicode编码"""
    result = ""
    for char in payload:
        if char.isascii() and char.isalnum():
            result += char
        else:
            result += f"\\u{ord(char):04x}"
    return result


def htmlencode(payload: str, **kwargs) -> str:
    """HTML实体编码"""
    result = ""
    for char in payload:
        if char.isalnum():
            result += char
        else:
            result += f"&#x{ord(char):x};"
    return result


def apostrophemask(payload: str, **kwargs) -> str:
    """单引号替换为UTF编码"""
    return payload.replace("'", "%EF%BC%87")


def apostrophenullencode(payload: str, **kwargs) -> str:
    """单引号后添加空字节"""
    return payload.replace("'", "%00'")


def appendnullbyte(payload: str, **kwargs) -> str:
    """末尾添加空字节"""
    return payload + "%00"


def randomcomments(payload: str, **kwargs) -> str:
    """随机插入注释"""
    result = ""
    for char in payload:
        if random.random() < 0.2 and char not in [' ', '\n', '\t']:
            comment = f"/*{''.join(random.choices(string.ascii_letters, k=random.randint(2,5)))}*/"
            result += comment + char
        else:
            result += char
    return result


def commentbeforeparentheses(payload: str, **kwargs) -> str:
    """括号前插入注释"""
    return re.sub(r'\(', '/**/(', payload)


def multiplespaces(payload: str, **kwargs) -> str:
    """单空格替换为多空格"""
    return re.sub(r' ', ' ' * random.randint(2, 5), payload)


def equaltolike(payload: str, **kwargs) -> str:
    """等号替换为LIKE"""
    return re.sub(r'(?i)=', ' LIKE ', payload)


def equaltorlike(payload: str, **kwargs) -> str:
    """等号替换为RLIKE"""
    return re.sub(r'(?i)=', ' RLIKE ', payload)


def symboliclogical(payload: str, **kwargs) -> str:
    """AND/OR替换为符号"""
    result = re.sub(r'(?i)\bAND\b', '&&', payload)
    result = re.sub(r'(?i)\bOR\b', '||', result)
    return result


def escapequotes(payload: str, **kwargs) -> str:
    """转义引号"""
    return payload.replace("'", "\\'").replace('"', '\\"')


def between(payload: str, **kwargs) -> str:
    """大于号替换为BETWEEN"""
    result = re.sub(r'(?i)>(\d+)', r'BETWEEN \1 AND 999999', payload)
    return result


def greatest(payload: str, **kwargs) -> str:
    """大于号替换为GREATEST"""
    result = re.sub(r'(?i)>(\d+)', r'GREATEST(\1,0)', payload)
    return result


def least(payload: str, **kwargs) -> str:
    """小于号替换为LEAST"""
    result = re.sub(r'(?i)<(\d+)', r'LEAST(\1,0)', payload)
    return result


def modsecurityversioned(payload: str, **kwargs) -> str:
    """ModSecurity版本注释绕过"""
    return re.sub(r'(?i)([A-Z]+)', r'/*!50000\1*/', payload)


def modsecurityzeroversioned(payload: str, **kwargs) -> str:
    """ModSecurity零版本注释绕过"""
    return re.sub(r'(?i)([A-Z]+)', r'/*!00000\1*/', payload)


def halfversionedmorekeywords(payload: str, **kwargs) -> str:
    """半版本注释关键字绕过"""
    keywords = ['SELECT', 'UNION', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'OR', 'AND']
    result = payload
    for kw in keywords:
        result = re.sub(f'(?i){kw}', f'/*!50000{kw}*/', result)
    return result


def versionedkeywords(payload: str, **kwargs) -> str:
    """版本注释关键字绕过"""
    keywords = ['SELECT', 'UNION', 'INSERT', 'UPDATE', 'DELETE', 'DROP']
    result = payload
    for kw in keywords:
        result = re.sub(f'(?i){kw}', f'/*!{kw}*/', result)
    return result


def versionedmorekeywords(payload: str, **kwargs) -> str:
    """更多版本注释关键字绕过"""
    keywords = ['SELECT', 'UNION', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'OR', 'AND', 'WHERE', 'FROM']
    result = payload
    for kw in keywords:
        result = re.sub(f'(?i){kw}', f'/*!50000{kw}*/', result)
    return result


def percentage(payload: str, **kwargs) -> str:
    """每个字符前添加百分号"""
    result = ""
    for char in payload:
        if char.isalnum():
            result += f"%{char}"
        else:
            result += char
    return result


def overlongutf8(payload: str, **kwargs) -> str:
    """超长UTF-8编码"""
    result = ""
    for char in payload:
        if char.isascii() and char.isalnum():
            result += char
        else:
            code = ord(char)
            if code < 128:
                result += f"%c0%{code:02x}"
            else:
                result += char
    return result


def scientific(payload: str, **kwargs) -> str:
    """科学计数法绕过"""
    result = re.sub(r'(\d+)', lambda m: f"{float(m.group(1)):.1e}", payload)
    return result


def ifnull2casewhenisnull(payload: str, **kwargs) -> str:
    """IFNULL替换为CASE WHEN ISNULL"""
    return re.sub(r'(?i)IFNULL\s*\(([^,]+),([^)]+)\)', r'CASE WHEN \1 IS NULL THEN \2 ELSE \1 END', payload)


def ifnull2ifisnull(payload: str, **kwargs) -> str:
    """IFNULL替换为IF(ISNULL)"""
    return re.sub(r'(?i)IFNULL\s*\(([^,]+),([^)]+)\)', r'IF(ISNULL(\1),\2,\1)', payload)


def concat2concatws(payload: str, **kwargs) -> str:
    """CONCAT替换为CONCAT_WS"""
    return re.sub(r'(?i)CONCAT\s*\(([^)]+)\)', r"CONCAT_WS('',\1)", payload)


def substring2leftright(payload: str, **kwargs) -> str:
    """SUBSTRING替换为LEFT/RIGHT"""
    result = re.sub(r'(?i)SUBSTRING\s*\(([^,]+),1,(\d+)\)', r'LEFT(\1,\2)', payload)
    result = re.sub(r'(?i)SUBSTRING\s*\(([^,]+),-(\d+),(\d+)\)', r'RIGHT(\1,\2)', result)
    return result


def ord2ascii(payload: str, **kwargs) -> str:
    """ORD替换为ASCII"""
    return re.sub(r'(?i)\bORD\b', 'ASCII', payload)


def sleep2getlock(payload: str, **kwargs) -> str:
    """SLEEP替换为GET_LOCK"""
    return re.sub(r'(?i)SLEEP\s*\((\d+)\)', r"GET_LOCK('sleep\1',\1)", payload)


def sp_password(payload: str, **kwargs) -> str:
    """MSSQL sp_password绕过"""
    return payload + ";sp_password"


def varnish(payload: str, **kwargs) -> str:
    """Vary头绕过"""
    return payload


def xforwardedfor(payload: str, **kwargs) -> str:
    """X-Forwarded-For绕过"""
    return payload


def luanginx(payload: str, **kwargs) -> str:
    """Lua Nginx绕过"""
    return payload


def luanginxmore(payload: str, **kwargs) -> str:
    """增强Lua Nginx绕过"""
    return payload


def bluecoat(payload: str, **kwargs) -> str:
    """BlueCoat绕过"""
    result = re.sub(r'(?i)SELECT', 'SELECT%09', payload)
    result = re.sub(r'(?i)FROM', '%09FROM', result)
    return result


def dunion(payload: str, **kwargs) -> str:
    """DUnion绕过"""
    return re.sub(r'(?i)UNION', 'DUNION', payload)


def misunion(payload: str, **kwargs) -> str:
    """MisUnion绕过"""
    return re.sub(r'(?i)UNION', '/*!UNION*/', payload)


def zeroeunion(payload: str, **kwargs) -> str:
    """0eUnion绕过"""
    return re.sub(r'(?i)UNION', '/*!00000UNION*/', payload)


TAMPER_SCRIPTS: Dict[str, Callable] = {
    'space2comment': space2comment,
    'space2plus': space2plus,
    'space2tab': space2tab,
    'space2newline': space2newline,
    'space2ifs': space2ifs,
    'randomcase': randomcase,
    'lowercase': lowercase,
    'uppercase': uppercase,
    'base64encode': base64encode,
    'urlencode': urlencode,
    'doubleurlencode': doubleurlencode,
    'charencode': charencode,
    'chardoubleencode': chardoubleencode,
    'hexencode': hexencode,
    'unicodeencode': unicodeencode,
    'htmlencode': htmlencode,
    'apostrophemask': apostrophemask,
    'apostrophenullencode': apostrophenullencode,
    'appendnullbyte': appendnullbyte,
    'randomcomments': randomcomments,
    'commentbeforeparentheses': commentbeforeparentheses,
    'multiplespaces': multiplespaces,
    'equaltolike': equaltolike,
    'equaltorlike': equaltorlike,
    'symboliclogical': symboliclogical,
    'escapequotes': escapequotes,
    'between': between,
    'greatest': greatest,
    'least': least,
    'modsecurityversioned': modsecurityversioned,
    'modsecurityzeroversioned': modsecurityzeroversioned,
    'halfversionedmorekeywords': halfversionedmorekeywords,
    'versionedkeywords': versionedkeywords,
    'versionedmorekeywords': versionedmorekeywords,
    'percentage': percentage,
    'overlongutf8': overlongutf8,
    'scientific': scientific,
    'ifnull2casewhenisnull': ifnull2casewhenisnull,
    'ifnull2ifisnull': ifnull2ifisnull,
    'concat2concatws': concat2concatws,
    'substring2leftright': substring2leftright,
    'ord2ascii': ord2ascii,
    'sleep2getlock': sleep2getlock,
    'sp_password': sp_password,
    'varnish': varnish,
    'xforwardedfor': xforwardedfor,
    'luanginx': luanginx,
    'luanginxmore': luanginxmore,
    'bluecoat': bluecoat,
    'dunion': dunion,
    'misunion': misunion,
    'zeroeunion': zeroeunion,
}


class TamperManager:
    """Tamper插件管理器"""
    
    def __init__(self):
        self.scripts = TAMPER_SCRIPTS.copy()
        self._custom_scripts: Dict[str, Callable] = {}
    
    def register(self, name: str, func: Callable) -> None:
        """注册自定义tamper脚本"""
        self._custom_scripts[name] = func
    
    def get_script(self, name: str) -> Optional[Callable]:
        """获取tamper脚本"""
        return self.scripts.get(name) or self._custom_scripts.get(name)
    
    def list_scripts(self) -> List[str]:
        """列出所有可用脚本"""
        return list(self.scripts.keys()) + list(self._custom_scripts.keys())
    
    def apply(self, payload: str, scripts: List[str], **kwargs) -> str:
        """应用多个tamper脚本"""
        result = payload
        for script_name in scripts:
            script = self.get_script(script_name)
            if script:
                try:
                    result = script(result, **kwargs)
                except Exception:
                    pass
        return result
    
    def apply_chain(self, payload: str, chains: List[List[str]], **kwargs) -> List[str]:
        """应用多个tamper链，返回所有变体"""
        results = [payload]
        for chain in chains:
            result = self.apply(payload, chain, **kwargs)
            if result != payload:
                results.append(result)
        return results
    
    def get_script_description(self, name: str) -> str:
        """获取脚本描述"""
        descriptions = {
            'space2comment': '空格替换为/**/注释',
            'space2plus': '空格替换为+号',
            'space2tab': '空格替换为Tab',
            'space2newline': '空格替换为换行符',
            'space2ifs': '空格替换为${IFS}变量',
            'randomcase': '随机大小写变换',
            'lowercase': '转换为小写',
            'uppercase': '转换为大写',
            'base64encode': 'Base64编码',
            'urlencode': 'URL编码',
            'doubleurlencode': '双重URL编码',
            'charencode': '字符URL编码',
            'chardoubleencode': '字符双重URL编码',
            'hexencode': '十六进制编码',
            'unicodeencode': 'Unicode编码',
            'htmlencode': 'HTML实体编码',
            'apostrophemask': '单引号UTF编码',
            'apostrophenullencode': '单引号后添加空字节',
            'appendnullbyte': '末尾添加空字节',
            'randomcomments': '随机插入注释',
            'commentbeforeparentheses': '括号前插入注释',
            'multiplespaces': '单空格替换为多空格',
            'equaltolike': '等号替换为LIKE',
            'equaltorlike': '等号替换为RLIKE',
            'symboliclogical': 'AND/OR替换为&&/||',
            'escapequotes': '转义引号',
            'between': '大于号替换为BETWEEN',
            'greatest': '大于号替换为GREATEST',
            'least': '小于号替换为LEAST',
            'modsecurityversioned': 'ModSecurity版本注释绕过',
            'modsecurityzeroversioned': 'ModSecurity零版本注释绕过',
            'halfversionedmorekeywords': '半版本注释关键字绕过',
            'versionedkeywords': '版本注释关键字绕过',
            'versionedmorekeywords': '更多版本注释关键字绕过',
            'percentage': '每个字符前添加百分号',
            'overlongutf8': '超长UTF-8编码',
            'scientific': '科学计数法绕过',
            'sp_password': 'MSSQL sp_password绕过',
            'bluecoat': 'BlueCoat绕过',
        }
        return descriptions.get(name, '无描述')


tamper_manager = TamperManager()
