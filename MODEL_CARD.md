# BugCrusher Hunter Model - Model Card

## Model Details
- **Base Model**: MiniMax 2.7
- **Fine-tuned by**: BugCrusher v3.5
- **Training Date**: 2026-04-16T22:55:15.476429
- **Training Data**: 3 examples

## Training Data Sources
1. Hunt reports from BugCrusher hunts
2. Weaponized attack vectors from vector_db
3. CVE exploitation knowledge

## Capabilities
- Autonomous vulnerability hunting
- XSS, SQLi, SSRF, RCE, IDOR detection
- GraphQL security testing
- Session hijack identification
- CVE-based exploitation

## Recommended Use
Fine-tune using the SFT format training corpus.
Use with low temperature (0.3) for consistent hunting behavior.

## Limitations
- Trained on bug bounty targets only
- Does not perform actual network attacks
- Requires human oversight for critical submissions
