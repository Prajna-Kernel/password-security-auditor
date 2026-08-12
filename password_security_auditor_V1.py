import getpass
import secrets
import hashlib
import string

def analyse_password(password):
    analysis = {
        "length": len(password),
        "uppercase": 0,
        "lowercase": 0,
        "digits": 0,
        "special": 0
    }

    common_passwords = [
        "123456",
        "password",
        "123456789",
        "qwerty",
        "12345678",
        "111111",
        "abc123"
    ]

    analysis["common_password"] = False

    analysis["character_types"] = 0
    score = 0

    for char in password:
        if char.isupper():
            analysis["uppercase"] += 1

        elif char.islower():
            analysis["lowercase"] += 1

        elif char.isdigit():
            analysis["digits"] += 1

        else:
            analysis["special"] += 1


    if analysis["uppercase"] > 0:
        analysis["character_types"] += 1

    if analysis["lowercase"] > 0:
        analysis["character_types"] += 1

    if analysis["digits"] > 0:
        analysis["character_types"] += 1

    if analysis["special"] > 0:
        analysis["character_types"] += 1

    if analysis["length"] >= 8:
        score += 1

    if analysis["length"] >= 12:
        score += 1

    if analysis["length"] >= 16:
        score += 1

    if analysis["character_types"] >= 2:
        score += 1

    if analysis["character_types"] >= 3:
        score += 1

    analysis["score"] = score

    if score <= 1:
        strength = "Very weak"
    elif score == 2:
        strength = "Weak"
    elif score == 3:
        strength = "Moderate"
    elif score == 4:
        strength = "Strong"

    else:
        strength = "Very strong"

    analysis["strength"] = strength

    if password.lower() in common_passwords:
        analysis["common_password"] = True

    return analysis

password = getpass.getpass("Enter password: ")

result = analyse_password(password)


print("\n===== Analysis Report =====")
print(f"Length: {result['length']}")
print(f"Uppercase: {result['uppercase']}")
print(f"Lowercase: {result['lowercase']}")
print(f"Digits: {result['digits']}")
print(f"Special characters: {result['special']}")
print(f"Character types: {result['character_types']}/4")
print(f"Score: {result['score']}/5")
print(f"Strength: {result['strength']}")
print(f"Common password: {result['common_password']}")
