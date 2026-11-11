"""Knowledge base: lessons, recovery playbooks and official US resources.

Written as plain-language summaries of public guidance from the FTC, FBI (IC3), CISA and
the organisations linked below. Defensive information only: how attacks work, how to
spot them, how to protect yourself and where to report.
"""

RESOURCES = {
    "FTC ReportFraud": ("https://reportfraud.ftc.gov", "Report scams and fraud to the Federal Trade Commission."),
    "IdentityTheft.gov": ("https://www.identitytheft.gov", "Official FTC site to report identity theft and get a recovery plan."),
    "FBI IC3": ("https://www.ic3.gov", "FBI Internet Crime Complaint Center: report online crime, especially money lost."),
    "FTC consumer advice": ("https://consumer.ftc.gov", "FTC guides on recognising and avoiding scams."),
    "CISA Secure Our World": ("https://www.cisa.gov/secure-our-world", "CISA basics: strong passwords, MFA, updates, recognising phishing."),
    "SSA Office of the Inspector General": ("https://oig.ssa.gov", "Report Social Security impersonation scams."),
    "StopNCII.org": ("https://stopncii.org", "Helps adults stop intimate images (real or fake) being shared on partner platforms."),
    "NCMEC Take It Down": ("https://takeitdown.ncmec.org", "Helps remove nude or sexual images of people under 18 from participating platforms."),
    "AnnualCreditReport.com": ("https://www.annualcreditreport.com", "The official free credit-report site."),
    "Google reverse image search": ("https://lens.google.com", "Check whether an image has appeared online before."),
    "TinEye": ("https://tineye.com", "Reverse image search engine."),
    "NCMEC CyberTipline": ("https://report.cybertip.org", "Report online sexual exploitation of children, including sextortion."),
    "988 Suicide & Crisis Lifeline": ("https://988lifeline.org", "Call or text 988, free and 24/7, if you feel overwhelmed or unsafe."),
}

LESSONS = {
    "Phishing (email, text, phone)": {
        "what": "Messages pretending to be a trusted company, bank or agency, designed to make you click a link, "
                "enter a password or code, or send money. By text it's called smishing; by phone, vishing.",
        "how": "Scammers copy logos and wording, create urgency (account locked, package held, unpaid toll) and send "
               "you to a fake website that looks real. Whatever you type there goes to them.",
        "signs": ["Urgent or threatening tone", "Asks you to click a link or log in", "Asks for a code, password or card number",
                  "Sender address or link domain doesn't match the real company", "Unexpected message about an account or delivery"],
        "protect": ["Don't click links in unexpected messages; go to the company's site or app yourself",
                    "Never share one-time codes; real companies don't ask for them",
                    "Turn on multi-factor authentication (MFA)", "Report phishing texts by forwarding them to 7726 (SPAM)"],
    },
    "Impersonation scams (bank, IRS, SSA, police)": {
        "what": "Someone pretends to be your bank, the IRS, Social Security, Medicare or police to scare you into paying "
                "or sharing information.",
        "how": "They may spoof caller ID, know some of your details, threaten arrest or account closure, and demand "
               "payment by gift card, wire, crypto or a payment app, or ask you to 'move money to keep it safe'.",
        "signs": ["Threats of arrest, fines or frozen accounts", "Payment by gift card, crypto, wire or payment app",
                  "Told to keep it secret or stay on the line", "Asked to move money to a 'safe account'"],
        "protect": ["Hang up and call the agency or bank using the number on its official website or your card",
                    "Government agencies don't demand gift cards or crypto",
                    "Never move money to a 'safe account' because someone told you to"],
    },
    "Tech-support scams": {
        "what": "Pop-ups, calls or emails claiming your computer is infected or a subscription will renew, pushing you "
                "to call a 'technician'.",
        "how": "The 'technician' asks you to install remote-access software, then steals data, installs malware or "
               "tricks you into paying for fake repairs or 'refunds'.",
        "signs": ["Pop-up with a phone number and alarm sounds", "Unexpected renewal or refund notice",
                  "Request to install AnyDesk, TeamViewer or similar"],
        "protect": ["Close the browser; real security warnings don't include phone numbers",
                    "Never give remote access to someone who contacted you",
                    "If you already did, disconnect from the internet and get help from a trusted source"],
    },
    "Romance and investment (crypto) scams": {
        "what": "A new online friend or partner builds trust over weeks, then introduces an 'investment' or asks for "
                "money for an emergency.",
        "how": "Fake trading sites show big gains to encourage larger deposits; withdrawals are blocked or need 'fees'. "
               "Sometimes called 'pig butchering'.",
        "signs": ["Met online, never meets in person or on video", "Pushes crypto or a trading app",
                  "Guaranteed or very high returns", "Asks for money, gift cards or crypto"],
        "protect": ["Never send money or crypto to someone you haven't met in person",
                    "Check investment platforms with official regulators before investing",
                    "Talk to a trusted friend or family member before sending money"],
    },
    "Ransomware and malware": {
        "what": "Malicious software that steals data or encrypts files and demands payment (ransom) to unlock them.",
        "how": "Often arrives through phishing attachments, fake downloads or unpatched software. Attackers may also "
               "threaten to leak stolen data.",
        "signs": ["Files suddenly unreadable with a ransom note", "Unknown programs or slow, unusual behaviour",
                  "Security tools turned off"],
        "protect": ["Keep devices and apps updated", "Back up important files offline or in the cloud",
                    "Don't open unexpected attachments", "Use reputable security software"],
    },
    "Data breaches and identity theft": {
        "what": "A company holding your data is hacked, or a criminal uses your personal details to open accounts, "
                "file taxes or take over your accounts.",
        "how": "Stolen passwords are tried on other sites (credential stuffing); stolen SSNs and birth dates are used "
               "for new accounts and loans.",
        "signs": ["Breach notification letter or email", "Accounts or credit inquiries you don't recognise",
                  "Bills or tax notices for things you didn't do"],
        "protect": ["Use a unique password per site (a password manager helps)", "Turn on MFA",
                    "Freeze your credit with Equifax, Experian and TransUnion (free)",
                    "Check your credit reports at AnnualCreditReport.com"],
    },
    "Deepfakes and voice cloning": {
        "what": "AI-generated or edited images, video or audio that make someone appear to say or do something they didn't.",
        "how": "A few seconds of audio from social media can clone a voice for a fake emergency call. Fake videos of "
               "celebrities promote scams; fake intimate images are used for harassment or sextortion.",
        "signs": ["Odd lighting, blurry edges around the face or hair", "Unnatural blinking or lip-sync",
                  "Distorted hands, teeth, ears or jewellery", "Garbled text in the image",
                  "Flat or robotic voice, odd pauses", "Urgent request for money or secrecy"],
        "protect": ["Agree a family 'safe word' for emergencies", "Call the person back on a number you already have",
                    "Limit public audio and video of yourself", "Use reverse image search on suspicious images"],
    },
    "Sextortion": {
        "what": "Someone threatens to share intimate images (real, stolen or fake) unless you pay or send more.",
        "how": "Often starts with a fake profile and fast flirting; then demands money, gift cards or crypto with a deadline.",
        "signs": ["New contact moves quickly to intimate content", "Threats with a short deadline", "Demands for payment"],
        "protect": ["Don't pay or send more; payment usually leads to more demands", "Save evidence, block, and report",
                    "Use StopNCII.org (adults) or NCMEC Take It Down (under 18)", "Report to the FBI at ic3.gov"],
    },
}

PLAYBOOKS = {
    "I clicked a link or entered my password": [
        "Change the password for that account right away, and anywhere you reused it.",
        "Turn on multi-factor authentication (MFA).",
        "Check the account for changes (recovery email, phone, forwarding rules) and sign out other sessions.",
        "If you entered card or bank details, call your bank using the number on your card.",
        "Run a security scan if you downloaded anything.",
        "Report the phishing message: forward texts to 7726; report to reportfraud.ftc.gov.",
    ],
    "I paid a scammer": [
        "Contact your bank, card issuer or payment app immediately and ask to stop or reverse the payment.",
        "Gift cards: contact the card company right away with the card number and receipt.",
        "Wire transfer or crypto: contact the transfer company or exchange immediately.",
        "Save evidence: messages, numbers, websites, receipts, transaction IDs.",
        "Report to the FBI at ic3.gov and to the FTC at reportfraud.ftc.gov.",
        "Watch for 'recovery' scammers who promise to get your money back for a fee.",
    ],
    "My identity was stolen": [
        "Go to IdentityTheft.gov to report it and get a personal recovery plan.",
        "Freeze your credit with Equifax, Experian and TransUnion (free).",
        "Check your credit reports at AnnualCreditReport.com.",
        "Contact the companies where fraud happened; close or freeze those accounts.",
        "Change passwords and turn on MFA on important accounts (email first).",
        "If your SSN was misused for taxes, follow the IRS identity-theft steps.",
    ],
    "Someone made a fake image or video of me": [
        "Don't engage with or pay anyone threatening you.",
        "Save evidence: screenshots, links, usernames, dates.",
        "Report the content to the platform where it appears (most have non-consensual imagery policies).",
        "Adults: use StopNCII.org; under 18: use NCMEC Take It Down.",
        "Report harassment or extortion to the FBI at ic3.gov and to local police.",
        "Talk to someone you trust; you are not at fault.",
    ],
    "I got a call from a family member in trouble": [
        "Stay calm and hang up.",
        "Call the family member, or another relative, on a number you already have.",
        "Ask a question only they would know, or use your family safe word.",
        "Never send gift cards, crypto or wire transfers because of an urgent call.",
        "Report it at reportfraud.ftc.gov.",
    ],
    "My computer may be infected or held for ransom": [
        "Disconnect from the internet (Wi-Fi off, cable out).",
        "Don't pay the ransom; it doesn't guarantee recovery and funds criminals.",
        "If it's a work device, contact your IT/security team immediately.",
        "Restore from a clean backup after the device is cleaned.",
        "Report to the FBI at ic3.gov; businesses can also report to CISA.",
    ],
}


# Deepfake situations: knowledge only (no uploads). Ordered by urgency.
DEEPFAKE_SITUATIONS = {
    "I'm being blackmailed with a fake (or real) intimate image or video": {
        "remember": "You are not at fault, and you are not alone. Fake images are made to scare you into paying "
                    "fast. Blackmailers usually move on when they don't get paid.",
        "steps": [
            "Don't pay and don't negotiate. Paying almost always leads to more demands, not deletion.",
            "Don't send any more images or information.",
            "Save evidence BEFORE blocking: screenshots of messages, the account name and profile link, the "
            "platform, dates, and any payment details (gift card, crypto wallet, payment app) they asked for.",
            "Stop replying and block the account after you've saved the evidence.",
            "Report the account and any posted content to the platform (most ban non-consensual intimate images, "
            "including AI-generated ones).",
            "Get images blocked from spreading: adults can use StopNCII.org, which creates a digital fingerprint "
            "on your own device (the image is never uploaded); under 18, use NCMEC Take It Down.",
            "Report the crime to the FBI at ic3.gov or your local FBI field office. If you're under 18 you can also "
            "report to the NCMEC CyberTipline (report.cybertip.org). You won't be in trouble for being a victim.",
            "Tell someone you trust: a friend, family member, school counselor or colleague.",
            "If you feel overwhelmed or unsafe, call or text 988 (Suicide & Crisis Lifeline), free and 24/7.",
        ],
        "law": "A 2025 federal law (the TAKE IT DOWN Act) makes publishing non-consensual intimate images, "
               "including AI-generated ones, a crime and requires covered platforms to remove reported images "
               "within 48 hours. Many states also have deepfake and image-abuse laws.",
    },
    "A fake image or video of me is being shared (harassment, rumours)": {
        "remember": "Content that impersonates you or shows you in fake situations usually breaks platform rules.",
        "steps": [
            "Save evidence: screenshots, links, account names, dates and where it was shared.",
            "Report it to each platform using its impersonation, harassment or synthetic-media report option.",
            "Ask people you trust to report it too, and not to share it, even to 'warn' others.",
            "If it's intimate content, use StopNCII.org (adults) or NCMEC Take It Down (under 18).",
            "If it threatens you, damages your work or school life, or keeps happening, report it to local police "
            "and consider talking to a lawyer; many states have laws covering deepfakes and harassment.",
            "If it's spreading widely, a short public statement ('this is fake, it has been reported') can help.",
        ],
    },
    "A call or voice message from someone I know asking for money": {
        "remember": "A few seconds of audio from social media is enough to clone a voice. Urgency is the trick.",
        "steps": [
            "Stay calm and hang up, even if the voice sounds exactly right.",
            "Call the person back on the number you already have, or contact another family member.",
            "Ask a question only they would know, or use your family safe word.",
            "Never send gift cards, crypto or wire transfers because of an urgent call.",
            "Report the call at reportfraud.ftc.gov.",
            "Agree a family safe word now, before it ever happens.",
        ],
    },
    "A celebrity or official is promoting crypto, money or a product": {
        "remember": "Fake celebrity videos are a common way to sell scam investments, 'free money' and miracle products.",
        "steps": [
            "Treat any celebrity video promising easy money, crypto returns or giveaways as a scam, whether "
            "or not the video itself is fake.",
            "Check the person's official, verified accounts or a trusted news source for the same message.",
            "Never send money, crypto or card details through links in the video or comments.",
            "Report the ad or video on the platform, and report losses to ic3.gov and reportfraud.ftc.gov.",
        ],
    },
    "An online contact whose photos might be fake (dating, social media)": {
        "remember": "Romance scammers often use stolen or AI-generated photos and avoid live video.",
        "steps": [
            "Run a reverse image search on their photos (Google Lens or TinEye): the same face under other "
            "names is a red flag.",
            "Ask for a live video call; repeated excuses are a warning sign.",
            "Never send money, gift cards or crypto to someone you haven't met in person.",
            "Be careful sharing intimate photos with new contacts; this is how many sextortion cases start.",
            "Report the profile to the platform and to reportfraud.ftc.gov.",
        ],
    },
    "A shocking image or video is going around online": {
        "remember": "Fakes spread fastest during breaking news, elections and disasters.",
        "steps": [
            "Pause before sharing; strong emotion is what fakes are designed to trigger.",
            "Check whether trusted news outlets or official accounts report the same thing.",
            "Look for the original source; reverse image search can show older versions.",
            "Look for the warning signs below.",
            "Don't share it 'just in case'; report it if it's misleading.",
        ],
    },
}

SPOTTING_TIPS = [
    ("Face and edges", "Blurry, smeared or flickering edges around the face, hair or ears."),
    ("Eyes", "Unnatural or missing blinking; reflections in the two eyes that don't match."),
    ("Mouth", "Lips slightly out of sync with the words; teeth that look blurred or odd."),
    ("Hands and details", "Extra or merged fingers, mismatched earrings or glasses, odd jewellery."),
    ("Lighting", "Shadows or lighting on the face that don't match the rest of the scene."),
    ("Background and text", "Garbled text, warped lines, objects that melt or repeat."),
    ("Voice", "Flat or robotic tone, odd pauses or breathing, unusual word choice."),
    ("Context", "Pressure to act fast, pay, or keep it secret: the strongest warning sign of all."),
]


def documents() -> list[dict]:
    """Flatten lessons and playbooks into passages for retrieval by the assistant."""
    docs = []
    for title, l in LESSONS.items():
        docs.append({"title": title, "kind": "lesson", "text": f"{title}. What it is: {l['what']}"})
        docs.append({"title": title, "kind": "lesson", "text": f"How {title.lower()} works: {l['how']}"})
        docs.append({"title": title, "kind": "lesson", "text": f"Signs of {title.lower()}: " + "; ".join(l["signs"]) + "."})
        docs.append({"title": title, "kind": "lesson", "text": f"How to protect yourself from {title.lower()}: "
                                                               + "; ".join(l["protect"]) + "."})
    for situation, steps in PLAYBOOKS.items():
        docs.append({"title": situation, "kind": "what to do", "text": f"{situation}. Steps: " + " ".join(
            f"{i}. {s}" for i, s in enumerate(steps, 1))})
    for situation, d in DEEPFAKE_SITUATIONS.items():
        docs.append({"title": situation, "kind": "deepfake help", "text": f"{situation}. {d['remember']} Steps: "
                     + " ".join(f"{i}. {x}" for i, x in enumerate(d["steps"], 1)) + (" " + d["law"] if "law" in d else "")})
    docs.append({"title": "How to spot a deepfake", "kind": "deepfake help",
                 "text": "How to spot a deepfake or fake video: " + "; ".join(f"{t}: {x}" for t, x in SPOTTING_TIPS)})
    for name, (url, desc) in RESOURCES.items():
        docs.append({"title": name, "kind": "resource", "text": f"{name} ({url}): {desc}"})
    return docs
