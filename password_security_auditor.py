# ============================================================
# IMPORTS
# ============================================================

import getpass
import secrets
import string
import math

# ============================================================
# PASSWORD ANALYSIS
# ============================================================

def analyse_password(password):
    analysis = {
        "length": len(password),
        "uppercase": 0,
        "lowercase": 0,
        "digits": 0,
        "special": 0,
        "entropy": 0,
        "entropy_strength": "",
        "character_pool": 0,
        "repeated_characters": False,
        "sequential_pattern": False,
        "warnings": [],
        "recommendations": []
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

    if analysis["lowercase"] > 0:
        analysis["character_pool"] += 26
    
    if analysis["uppercase"] > 0:
        analysis["character_pool"] += 26
    
    if analysis["digits"] > 0:
        analysis["character_pool"] += 10
    
    if analysis["special"] > 0:
        analysis["character_pool"] += 32

    if analysis["character_pool"] > 0:
        analysis["entropy"] = (
            analysis["length"] * math.log2(analysis["character_pool"])
        )

    if analysis["entropy"] < 28:
        analysis["entropy_strength"] = "Very low"

    elif analysis["entropy"] < 36:
        analysis["entropy_strength"] = "Low"

    elif analysis["entropy"] < 60:
        analysis["entropy_strength"] = "Moderate"

    elif analysis["entropy"] < 80:
        analysis["entropy_strength"] = "Strong"

    else:
        analysis["entropy_strength"] = "Very strong"

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

    if password.lower() in common_passwords:
        analysis["common_password"] = True

    if len(password) > 1:
        for i in range(1, len(password)):
            if password[i] == password[i - 1]:
                analysis["repeated_characters"] = True
                break


    sequences = [
        "1234567890",
        "abcdefghijklmnopqrstuvwxyz",
        "qwertyuiopasdfghjklzxcvbnm"
    ]

    password_lower = password.lower()

    for sequence in sequences:
        for i in range(len(sequence) - 3):
            pattern = sequence[i:i + 4]

            if pattern in password_lower:
                analysis["sequential_pattern"] = True
                break

        if analysis["sequential_pattern"]:
            break

    if analysis["common_password"]:
        analysis["warnings"].append(
            "Password appears in the common-password list."
        )

    if analysis["repeated_characters"]:
        analysis["warnings"].append(
            "Password contains repeated consecutive characters."
        )

    if analysis["sequential_pattern"]:
        analysis["warnings"].append(
            "Password contains a sequential pattern."
        )

    if analysis["length"] < 8:
        analysis["warnings"].append(
            "Password is shorter than 8 characters."
        )

    if analysis["common_password"]:
        analysis["recommendations"].append(
            "Choose a password that is not commonly used."
    )

    if analysis["repeated_characters"]:
        analysis["recommendations"].append(
            "Avoid repeated consequetive characters."
    )

    if analysis["sequential_pattern"]:
        analysis["recommendations"].append(
            "Avoid predictable sequences such as 1234 or abcd."
        )

    if analysis["length"] < 12:
        analysis["recommendations"].append(
            "Use a longer password, preferable at least 12 characters."
        )

    if analysis["character_types"] < 3:
        analysis["recommendations"].append(
            "Use a combination of different character types."
        )

    if analysis["entropy"] < 60:
        analysis["recommendations"].append(
            "Use a longer and less predictable password."
        )

    # Reduce score for detected weaknesses
    
    if analysis["common_password"]:
        score -= 2 
    
    if analysis["repeated_characters"]:
        score -= 1 
    
    if analysis["sequential_pattern"]:
        score -= 1
    
    if score < 0:
        score = 0

    analysis["score"] = score

    # Determine final strength

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

    
    return analysis

# ============================================================
# ANALYSE MODE
# ============================================================

def analyse_mode():
    password = getpass.getpass("Enter password: ")

    result = analyse_password(password)

    print(f"\n===== Security Warnings =====")

    if not result["warnings"]:
        print("No major weakness detected.")

    else:
        for warning in result["warnings"]:
            print(f"- {warning}")

    print(f"\n===== Recommendations =====")

    if not result["recommendations"]:
        print("No recommendations. Password meets the current checks.")

    else:
        for recommendation in result["recommendations"]:
            print(f"- {recommendation}")

    print("\n===== Analysis Report =====")
    print(f"Length: {result['length']}")
    print(f"Uppercase: {result['uppercase']}")
    print(f"Lowercase: {result['lowercase']}")
    print(f"Digits: {result['digits']}")
    print(f"Special characters: {result['special']}")
    print(f"Character types: {result['character_types']}/4")
    print(f"Character pool: {result['character_pool']}")
    print(f"Score: {result['score']}/5")
    print(f"Strength: {result['strength']}")
    print(f"Common password: {result['common_password']}")
    print(f"Estimated entropy: {result['entropy']:.1f} bits")
    print(f"Entropy strength: {result['entropy_strength']}")

# ============================================================
# PASSWORD GENERATION
# ============================================================

def generate_password(length, use_lowercase=True, use_uppercase=True,
                      use_digits=True, use_special=True):

    character_sets = []


    if use_lowercase:
        character_sets.append(string.ascii_lowercase)

    if use_uppercase:
        character_sets.append(string.ascii_uppercase)

    if use_digits:
        character_sets.append(string.digits)

    if use_special:
        character_sets.append(string.punctuation)

    if not character_sets:
        raise ValueError("At least one character type must be selected.")

    if length < len(character_sets):
        raise ValueError(
            "Password length is too short for the selected character types."
            )

    if length < 4:
        raise ValueError("Password length must be at least 4.")

    characters = "".join(character_sets)

    password_characters = []

    # Guarantee at least one character from every selected type
    for character_set in character_sets:
        password_characters.append(secrets.choice(character_set))

    # Fill the remaining positions
    for _ in range(length - len(character_sets)):
        password_characters.append(secrets.choice(characters))

    # Randomize the positions
    secrets.SystemRandom().shuffle(password_characters)

    return "".join(password_characters)

# ============================================================
# GENERATE MODE
# ============================================================

def generate_mode():
    print("\n===== Generator Settings =====")

    use_lowercase = input("Include lowercase letters? (y/n): ").lower() == "y"
    use_uppercase = input("Include uppercase letters? (y/n): ").lower() == "y"
    use_digits = input("Include digits? (y/n): ").lower() == "y"
    use_special = input("Include special characters? (y/n): ").lower() == "y"

    if not any([
        use_lowercase,
        use_uppercase,
        use_digits,
        use_special
    ]):
        print("At least one character type must be selected.")
        return

    while True:
        length_input = input("Enter password length: ")

        if not length_input.isdigit():
            print("Please enter a valid number.")
            continue

        length = int(length_input)

        selected_types = sum([
            use_lowercase,
            use_uppercase,
            use_digits,
            use_special
        ])

        if length < 4:
            print("Password length must be at least 4 characters.")
            continue

        if length < selected_types:
            print(
                f"Password length must be at least "
                f"{selected_types} characters."
            )
            continue

        break

    print("\n===== Generator Settings =====")
    print(f"Lowercase: {'Yes' if use_lowercase else 'No'}")
    print(f"Uppercase: {'Yes' if use_uppercase else 'No'}")
    print(f"Digits: {'Yes' if use_digits else 'No'}")
    print(f"Special: {'Yes' if use_special else 'No'}")
    print(f"Length: {length}")

    generated = generate_password(
        length,
        use_lowercase,
        use_uppercase,
        use_digits,
        use_special
    )

    generated_analysis = analyse_password(generated)

    print("\n===== Generated password =====") 
    print(generated)
    print("\n===== Generated Password Analysis =====")
    print(f"Length: {generated_analysis['length']}")
    print(f"Uppercase: {generated_analysis['uppercase']}")
    print(f"Lowercase: {generated_analysis['lowercase']}")
    print(f"Digits: {generated_analysis['digits']}")
    print(f"Special characters: {generated_analysis['special']}")
    print(f"Character types: {generated_analysis['character_types']}/4")
    print(f"Character pool: {generated_analysis['character_pool']}")
    print(f"Estimated entropy: {generated_analysis['entropy']:.1f} bits")
    print(f"Entropy strength: {generated_analysis['entropy_strength']}")
    print(f"Strength: {generated_analysis['strength']}")

# ============================================================
# MAIN MENU
# ============================================================

while True:
    print("\n===== Password security toolkit =====")
    print("1. Analyse a password.")
    print("2. Generate a password.")
    print("3. Exit.")

    choice = input("Choose an option: ").strip()

    if choice == "1":
        analyse_mode()

    elif choice == "2":
        generate_mode()
    
    elif choice == "3":
        print("Goodbye...")
        break

    else:
        print("Invalid option. Please choose 1, 2 or 3.")