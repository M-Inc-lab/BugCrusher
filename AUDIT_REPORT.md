# Audit Report: BugCrusher
**Date:** 2026-04-20T20:40:31.481190 | **Auditor:** v2

## Summary

| Metric | Value |
|--------|-------|
| Files Analyzed | 24 |
| Tests | 0 PASS / 1 FAIL |
| Mutation Score | 83% |
| Security Issues | 6 |
| Logic Bugs | 66 |

## Security (6)

- CRITICAL: Cmd Inj: shell=True L86
- CRITICAL: Cmd Inj: shell=True L98
- CRITICAL: Cmd Inj: shell=True L109
- CRITICAL: Cmd Inj: shell=True L124
- CRITICAL: Cmd Inj: shell=True L153
- CRITICAL: Cmd Inj: shell=True L189

## Logic (66)

- LOW: Bare except: L89
- LOW: Bare except: L101
- LOW: Bare except: L112
- LOW: Bare except: L128
- LOW: Bare except: L200
- LOW: Bare except: L240
- LOW: Bare except: L345
- LOW: Bare except L89
- LOW: Bare except L101
- LOW: Bare except L112
- LOW: Bare except L128
- LOW: Bare except L200
- LOW: Bare except L240
- LOW: Bare except L345
- LOW: Bare except: L44
- LOW: printf fmt L167
- LOW: Bare except L44
- LOW: Bare except: L46
- LOW: Bare except: L59
- LOW: Bare except: L68
- LOW: Bare except: L76
- LOW: Bare except: L85
- LOW: Bare except: L109
- LOW: Bare except: L142
- LOW: range(len) L113
- LOW: Bare except L46
- LOW: Bare except L59
- LOW: Bare except L68
- LOW: Bare except L76
- LOW: Bare except L85
- LOW: Bare except L109
- LOW: Bare except L142
- LOW: Bare except: L120
- LOW: Bare except L120
- LOW: Bare except: L129
- LOW: Bare except: L135
- LOW: Bare except: L147
- LOW: Bare except: L159
- LOW: range(len) L90
- LOW: Bare except L129
- LOW: Bare except L135
- LOW: Bare except L147
- LOW: Bare except L159
- LOW: Bare except: L51
- LOW: Bare except L51
- LOW: Bare except: L82
- LOW: Bare except: L95
- LOW: Bare except: L110
- LOW: Bare except L82
- LOW: Bare except L95
- LOW: Bare except L110
- LOW: Bare except: L47
- LOW: Bare except: L58
- LOW: Bare except: L128
- LOW: Bare except L47
- LOW: Bare except L58
- LOW: Bare except L128
- LOW: Bare except: L166
- LOW: Bare except L166
- LOW: Bare except: L53
- LOW: Bare except: L74
- LOW: Bare except: L104
- LOW: Bare except L53
- LOW: Bare except L74
- LOW: Bare except L104
- LOW: printf fmt L342

*Multi-Test Auditor v2*
