# GhostMap Tampers Reference

This directory contains 69 tamper scripts inherited from sqlmap upstream
(70 minus the EOL `bluecoat.py` removed in GhostMap).
They are **payload transformation primitives** — they don't bypass WAFs by
themselves, they apply transformations that may evade specific filtering
rules depending on the target's configuration.

## When to use tampers

Use tampers when:

1. Your engagement Rules of Engagement **explicitly authorize** WAF/filter
   bypass attempts.
2. You've already identified what's blocking the payloads (status 403,
   specific WAF response, signature filter, etc.) and have a hypothesis
   about which transformation might evade it.

Do **not** use tampers as a default scattershot. Pick what fits the target.

## Tampers by category

### Whitespace handling
| Tamper | What it does | Best for |
|---|---|---|
| `space2comment` | spaces → `/**/` | Generic SQL filters that strip spaces |
| `space2dash` | spaces → `--` + newline | DBMS that accept comment-style spaces |
| `space2hash` | spaces → `#` + newline | MySQL with hash comments |
| `space2plus` | spaces → `+` | URL-decoded contexts |
| `space2randomblank` | spaces → random whitespace char | Naive blocklists |
| `space2morecomment` | spaces → `/**_**/` | More aggressive comment evasion |
| `space2morehash` | spaces → `#hash + random` | MySQL aggressive |
| `space2mssqlblank` | spaces → MSSQL whitespace chars | Microsoft SQL Server |
| `space2mssqlhash` | spaces → MSSQL `%23` | Microsoft SQL Server |
| `space2mysqlblank` | spaces → MySQL whitespace chars | MySQL |
| `space2mysqldash` | spaces → MySQL `--` style | MySQL |
| `multiplespaces` | adds extra spaces around keywords | Naive normalizers |
| `commalesslimit` | `LIMIT 0,1` → `LIMIT 1 OFFSET 0` | MySQL |
| `commalessmid` | `MID(a, 1, 2)` → `MID(a FROM 1 FOR 2)` | MySQL |

### Encoding
| Tamper | What it does | Best for |
|---|---|---|
| `charencode` | URL-encode characters | Naive content filters |
| `chardoubleencode` | double URL-encode | Filters that decode once |
| `charunicodeencode` | unicode-encode characters | Some IIS / .NET stacks |
| `charunicodeescape` | `\u` escape sequences | Specific JS contexts |
| `htmlencode` | HTML-encode characters | Filters not normalizing HTML entities |
| `decentities` | decimal HTML entities | Naive HTML filters |
| `hexentities` | hex HTML entities | Naive HTML filters |
| `hex2char` | `0x...` hex → CHAR() | Where 0x is filtered |
| `ord2ascii` | `ORD()` → `ASCII()` | Some DBMS |
| `base64encode` | base64 encode payload | When payload arrives base64-encoded |
| `binary` | `BINARY` operator wrapping | Some DBMS string comparison filters |
| `overlongutf8` | overlong UTF-8 encoding | Filters that don't normalize UTF-8 |
| `overlongutf8more` | aggressive overlong UTF-8 | Same, more aggressive |
| `escapequotes` | escape quotes with `\` | Some PHP/MySQL contexts |
| `apostrophenullencode` | `'` → `%00%27` | Filters dropping null bytes |
| `apostrophemask` | `'` → UTF-8 fullwidth apostrophe | Some JS-side filters |
| `appendnullbyte` | append `%00` | Some C-string parsers |
| `unmagicquotes` | bypass PHP magic_quotes | Legacy PHP |
| `percentage` | insert `%` chars between letters | Some specific filters |

### Case / Identifier obfuscation
| Tamper | What it does | Best for |
|---|---|---|
| `randomcase` | random-case keywords | Case-sensitive blocklists |
| `lowercase` | force lowercase | Some normalizers |
| `uppercase` | force uppercase | Some normalizers |

### Comment injection
| Tamper | What it does | Best for |
|---|---|---|
| `randomcomments` | random `/**/` between letters | Naive keyword filters |
| `versionedkeywords` | MySQL `/*!50000UNION*/` | MySQL versioned comments |
| `versionedmorekeywords` | aggressive versioned comments | MySQL |
| `halfversionedmorekeywords` | half versioned style | MySQL |
| `commentbeforeparentheses` | comment before `(` | Some MSSQL |
| `informationschemacomment` | comment in INFORMATION_SCHEMA | MySQL |
| `modsecurityversioned` | versioned comments to evade ModSec | ModSecurity (still maintained) |
| `modsecurityzeroversioned` | zero-versioned comments to evade ModSec | ModSecurity |
| `sp_password` | `sp_password` trick (MSSQL) | Microsoft SQL Server |

### Function / operator substitution
| Tamper | What it does | Best for |
|---|---|---|
| `equaltolike` | `=` → `LIKE` | Filters blocking `=` |
| `equaltorlike` | `=` → `RLIKE` | MySQL |
| `concat2concatws` | `CONCAT()` → `CONCAT_WS()` | MySQL |
| `if2case` | `IF()` → `CASE WHEN` | Generic |
| `ifnull2casewhenisnull` | `IFNULL` → `CASE WHEN ... IS NULL` | Generic |
| `ifnull2ifisnull` | `IFNULL` → `IF(... IS NULL ...)` | MySQL |
| `greatest` | `>` → `GREATEST(...)` | Where comparison ops blocked |
| `least` | `<` → `LEAST(...)` | Where comparison ops blocked |
| `substring2leftright` | `SUBSTRING` → `LEFT/RIGHT` | Generic |
| `symboliclogical` | `AND/OR` → `&&/\|\|` | MySQL |
| `sleep2getlock` | `SLEEP()` → `GET_LOCK()` | MySQL where SLEEP filtered |
| `scientific` | numbers → scientific notation | Naive numeric filters |
| `unionalltounion` | `UNION ALL` → `UNION` | Where ALL filtered |
| `0eunion` | `0eUNION` (scientific notation prefix) | Some specific bypass |
| `dunion` | `DUNION` keyword variant | Some MSSQL |
| `misunion` | misspelled UNION variants | Naive blocklists |
| `schemasplit` | `database.table` → split schema reference | Various |
| `plus2concat` | `+` → `CONCAT()` (MSSQL) | Microsoft SQL Server |
| `plus2fnconcat` | `+` → `{fn CONCAT}` | MSSQL ODBC |

### Specific WAF/proxy oriented (target product still in use)
| Tamper | Target |
|---|---|
| `varnish` | Varnish Cache (still maintained) |
| `luanginx` | OpenResty / Lua-Nginx (still maintained) |
| `luanginxmore` | OpenResty / Lua-Nginx aggressive |
| `xforwardedfor` | adds X-Forwarded-For random IP |

## Recommended combinations by stack

These are starting points. Adjust based on what you actually see being
blocked on the target.

### Generic MySQL behind a generic filter
```
--tamper=between,space2comment,randomcase
```

### Microsoft SQL Server
```
--tamper=between,space2mssqlblank,charunicodeencode
```

### PHP + MySQL behind ModSecurity
```
--tamper=modsecurityversioned,space2comment,randomcase
```

### IIS + .NET + MSSQL
```
--tamper=between,charunicodeencode,space2mssqlblank,sp_password
```

### Aggressive (last resort, may be very slow)
```
--tamper=between,charunicodeencode,space2morecomment,modsecurityzeroversioned,randomcase,apostrophenullencode
```

## Removed in GhostMap

- `bluecoat.py` — Symantec Blue Coat was acquired by Broadcom in 2016
  and is no longer a standalone product. Removed in GhostMap because
  the target it was designed for is end-of-life.

## License

All tampers in this directory inherit the GPLv2 license from sqlmap
upstream. They are unmodified primitives, GhostMap only curates and
documents them.
