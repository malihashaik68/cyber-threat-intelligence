"""Attack types and sectors, detected with whole-word keyword patterns.

Attack types follow the categories US agencies (FBI IC3, FTC, CISA) commonly report.
Each pattern is a regular expression matched case-insensitively on whole words.
"""
import re

ATTACK_TYPES = {
    "Ransomware": [r"ransomware", r"ransom", r"encrypt(?:ed|s)? (?:files|data|systems)", r"lockbit", r"blackcat"],
    "Phishing": [r"phishing", r"phish(?:ed|ers?)?", r"smishing", r"vishing", r"spear[- ]phishing", r"credential harvesting"],
    "Data breach": [r"data breach(?:es)?", r"breach(?:ed)?", r"data leak", r"leaked", r"exposed (?:data|records)", r"stolen data", r"records exposed"],
    "Malware": [r"malware", r"trojan", r"spyware", r"infostealer", r"botnet", r"backdoor", r"virus", r"worm"],
    "DDoS": [r"ddos", r"denial[- ]of[- ]service"],
    "Scam & fraud": [r"scam(?:s|mers?)?", r"fraud(?:sters?)?", r"con artists?", r"romance scam", r"tech support scam",
                     r"investment scam", r"pig butchering", r"impersonat(?:ion|ing|ed)"],
    "Identity theft": [r"identity theft", r"stolen identit(?:y|ies)", r"social security numbers?", r"account takeover"],
    "Deepfake & AI abuse": [r"deepfakes?", r"voice clon(?:e|ing)", r"ai[- ]generated", r"synthetic media", r"face swap"],
    "Vulnerability & exploit": [r"vulnerabilit(?:y|ies)", r"zero[- ]day", r"exploit(?:ed|s)?", r"cve-\d{4}-\d+", r"patch(?:ed|es)?", r"flaw"],
    "Nation-state & espionage": [r"nation[- ]state", r"state[- ]sponsored", r"espionage", r"apt\d+", r"spy(?:ing)?"],
    "Supply chain": [r"supply[- ]chain"],
    "Cyberbullying & extortion": [r"sextortion", r"extortion", r"harass(?:ment|ed)", r"blackmail"],
    "Hacking / cyberattack (general)": [r"hack(?:ed|ers?|ing|s)?", r"cyber[- ]?attacks?", r"cyber[- ]?incidents?", r"intrusion"],
}

SECTORS = {
    "Finance & banking": [r"banks?", r"banking", r"financial", r"finance", r"payments?", r"credit cards?", r"crypto(?:currency)?", r"atm"],
    "Healthcare": [r"hospitals?", r"health(?:care)?", r"medical", r"clinics?", r"patients?", r"pharma(?:ceutical)?"],
    "Government": [r"government", r"federal", r"agenc(?:y|ies)", r"ministry", r"military", r"defen[cs]e", r"election", r"council"],
    "Energy & utilities": [r"energy", r"power (?:grid|plant|station)s?", r"electric(?:ity)?", r"utilit(?:y|ies)", r"oil", r"gas pipeline", r"water (?:system|utility|supply)", r"nuclear", r"grid"],
    "Telecommunications": [r"telecom(?:munications)?", r"5g", r"carriers?", r"mobile networks?", r"broadband"],
    "Education": [r"schools?", r"universit(?:y|ies)", r"college", r"students?"],
    "Retail & consumer": [r"retail(?:ers?)?", r"stores?", r"shoppers?", r"e-?commerce", r"consumers?", r"customers?"],
    "Technology": [r"software", r"cloud", r"tech (?:company|firm|giant)s?", r"microsoft", r"google", r"apple", r"meta", r"amazon", r"app(?:s)?"],
    "Transportation": [r"airlines?", r"airports?", r"rail(?:way)?", r"shipping", r"ports?", r"logistics", r"transport"],
    "Manufacturing": [r"manufactur(?:er|ers|ing)", r"factor(?:y|ies)", r"industrial"],
}

_compiled = lambda table: {k: re.compile(r"\b(?:" + "|".join(v) + r")\b", re.I) for k, v in table.items()}
_ATTACK_RE, _SECTOR_RE = _compiled(ATTACK_TYPES), _compiled(SECTORS)


def detect_attack_types(text: str) -> list[str]:
    return [k for k, rx in _ATTACK_RE.items() if rx.search(text or "")]


def detect_sectors(text: str) -> list[str]:
    return [k for k, rx in _SECTOR_RE.items() if rx.search(text or "")]
