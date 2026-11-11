"""Location detection for news text: US states, major US cities and countries.

Whole-word, case-insensitive matching on the ORIGINAL text (not the cleaned text),
so "UK" does not match "Ukraine" and "Indiana" is not read as "India".
"""
import re

US_STATES = ["Alabama", "Alaska", "Arizona", "Arkansas", "California", "Colorado", "Connecticut", "Delaware",
             "Florida", "Georgia", "Hawaii", "Idaho", "Illinois", "Indiana", "Iowa", "Kansas", "Kentucky",
             "Louisiana", "Maine", "Maryland", "Massachusetts", "Michigan", "Minnesota", "Mississippi", "Missouri",
             "Montana", "Nebraska", "Nevada", "New Hampshire", "New Jersey", "New Mexico", "New York",
             "North Carolina", "North Dakota", "Ohio", "Oklahoma", "Oregon", "Pennsylvania", "Rhode Island",
             "South Carolina", "South Dakota", "Tennessee", "Texas", "Utah", "Vermont", "Virginia", "Washington",
             "West Virginia", "Wisconsin", "Wyoming", "District of Columbia"]

# Major cities -> state (helps when articles name a city but not the state)
US_CITIES = {"New York City": "New York", "Los Angeles": "California", "San Francisco": "California",
             "San Diego": "California", "San Jose": "California", "Chicago": "Illinois", "Houston": "Texas",
             "Dallas": "Texas", "Austin": "Texas", "San Antonio": "Texas", "Phoenix": "Arizona",
             "Philadelphia": "Pennsylvania", "Pittsburgh": "Pennsylvania", "Seattle": "Washington",
             "Boston": "Massachusetts", "Atlanta": "Georgia", "Miami": "Florida", "Orlando": "Florida",
             "Tampa": "Florida", "Denver": "Colorado", "Detroit": "Michigan", "Minneapolis": "Minnesota",
             "Las Vegas": "Nevada", "Baltimore": "Maryland", "Nashville": "Tennessee", "Portland": "Oregon",
             "Charlotte": "North Carolina", "Columbus": "Ohio", "Cleveland": "Ohio", "Newark": "New Jersey",
             "Jersey City": "New Jersey", "New Orleans": "Louisiana", "Salt Lake City": "Utah",
             "Washington, D.C.": "District of Columbia", "Washington DC": "District of Columbia"}

COUNTRIES = {"United States": "United States", "USA": "United States", "U.S.": "United States", "US": "United States",
             "America": "United States", "United Kingdom": "United Kingdom", "UK": "United Kingdom",
             "Britain": "United Kingdom", "England": "United Kingdom", "China": "China", "Russia": "Russia",
             "Iran": "Iran", "North Korea": "North Korea", "Ukraine": "Ukraine", "India": "India",
             "Germany": "Germany", "France": "France", "Canada": "Canada", "Australia": "Australia",
             "Japan": "Japan", "Singapore": "Singapore", "Israel": "Israel", "Brazil": "Brazil",
             "South Korea": "South Korea", "Taiwan": "Taiwan", "Netherlands": "Netherlands", "Italy": "Italy",
             "Spain": "Spain", "Mexico": "Mexico", "Ireland": "Ireland", "Poland": "Poland",
             # adjectives used in headlines ("Russian hackers")
             "American": "United States", "British": "United Kingdom", "Chinese": "China", "Russian": "Russia",
             "Iranian": "Iran", "North Korean": "North Korea", "Ukrainian": "Ukraine", "Indian": "India",
             "Israeli": "Israel", "German": "Germany", "French": "France", "Canadian": "Canada"}
CASE_SENSITIVE = {"US", "UK", "USA", "U.S."}  # avoid matching the word "us"


def _find(text: str, name: str) -> bool:
    flags = 0 if name in CASE_SENSITIVE else re.I
    return re.search(rf"(?<![\w.]){re.escape(name)}(?![\w])", text, flags) is not None


def detect_locations(text: str) -> dict:
    """Return {"states": [...], "cities": [...], "countries": [...]} found in the text."""
    text = text or ""
    cities = [c for c in US_CITIES if _find(text, c)]
    states = {s for s in US_STATES if _find(text, s)}
    states |= {US_CITIES[c] for c in cities}
    # "New York" as a state is ambiguous with the city; "Washington" usually means DC/government
    if "Washington" in states and not re.search(r"Washington state|state of Washington", text, re.I):
        states.discard("Washington")
    if "Virginia" in states and _find(text, "West Virginia") and not re.search(r"(?<!West )Virginia", text):
        states.discard("Virginia")
    # remove US state names first so "New Mexico" is not read as Mexico
    without_states = text
    for s in US_STATES:
        without_states = re.sub(rf"\b{re.escape(s)}\b", " ", without_states, flags=re.I)
    countries = {v for k, v in COUNTRIES.items() if _find(without_states, k)}
    if states or cities:
        countries.add("United States")
    return {"states": sorted(states), "cities": sorted(cities), "countries": sorted(countries)}
