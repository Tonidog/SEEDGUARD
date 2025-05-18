# Main Project: SEEDGUARD.IO
#
# Program: SeedGuardBip39Checker
#
# Version: 1.1.2 (Release Date: May 18, 2025)
#
# GitHub: https://github.com/SecureData/DataGuardian
#
# Project Summary:
#
# Disclaimer:
#
# The SEEDGUARD.IO development team is not responsible for any consequences resulting from the use of the
# SeedGuardBip39Checker program.
# Users operate the program at their own risk. We strongly recommend reading the documentation
# and following the security guidelines.
#
# Security Warning:
# Please note that ANY information on your computer can be compromised.
# There is a risk of third-party access to your data. Do not store or enter your working seed phrase on any computer,
# phone, or internet-connected device.
# For additional protection of your private information, please review our security recommendations:
#
# https://github.com/SecureData/DataGuardian/blob/main/security-recommendations.md
#
# About Donations:
#
# Your donations inspire and support the SecureData development team in improving the DataGuardian project.
# Thanks to your help, we can introduce new features, enhance security, and make the program even better for all users.
# If you like our work, you can support us by sending a donation to the ETH address: 0x0000. ETH, USDT,
# USDC are accepted, and you can use the ARBITRUM network.


import hashlib
import os

# Global list to hold BIP39 English words loaded from external file
BIP39_WORDLIST = []

# Load BIP39 wordlist from a file formatted as "0001\tabandon"
def load_bip39_wordlist(filename="bip39_wordlist.txt"):
    global BIP39_WORDLIST
    if not os.path.exists(filename):
        print("Error: BIP39 wordlist file not found")
        exit(1)
    with open(filename, 'r', encoding='utf-8') as file:
        for line in file:
            parts = line.strip().split('\t')
            if len(parts) == 2:
                BIP39_WORDLIST.append(parts[1])

# Convert mnemonic words to entropy and validate checksum
# Returns True if valid checksum, False otherwise
def mnemonic_to_entropy(mnemonic_words):
    try:
        indexes = [BIP39_WORDLIST.index(word) for word in mnemonic_words]
    except ValueError:
        return False

    bits = ''.join(bin(index)[2:].zfill(11) for index in indexes)
    entropy_length = (len(bits) * 32) // 33
    entropy_bits = bits[:entropy_length]
    checksum_bits = bits[entropy_length:]

    entropy_bytes = int(entropy_bits, 2).to_bytes(entropy_length // 8, 'big')
    hash_bytes = hashlib.sha256(entropy_bytes).digest()
    hash_bits = bin(int.from_bytes(hash_bytes, 'big'))[2:].zfill(256)

    return checksum_bits == hash_bits[:len(checksum_bits)]

# Read 24 mnemonic words or 4-digit codes from sguard.dat file and validate their format
def read_sguard_file(filename="sguard.dat"):
    if not os.path.exists(filename):
        print("Error: data file not found")
        return None

    with open(filename, 'r') as file:
        lines = file.read().splitlines()

    if len(lines) != 24:
        print("Error: no data")
        return None

    words = []
    mode = None  # 'word' or 'code'

    for line in lines:
        parts = line.strip().split()
        if len(parts) != 2 or not parts[0].isdigit():
            print("Error: no data")
            return None

        token = parts[1]

        if token.isdigit() and len(token) == 4:
            if mode is None:
                mode = 'code'
            elif mode != 'code':
                print("Error: no data")
                return None

            index = int(token)
            if not (1 <= index <= len(BIP39_WORDLIST)):
                print("Error: no data")
                return None
            words.append(BIP39_WORDLIST[index - 1])

        else:
            if mode is None:
                mode = 'word'
            elif mode != 'word':
                print("Error: no data")
                return None

            if token not in BIP39_WORDLIST:
                print("Error: no data")
                return None
            words.append(token)

    return words

# Write corrected mnemonic phrase with indexes and KD offset to sguard.dat
# Format: "01 0001 word" for each word, followed by "KD = offset"
def write_sguard_file(words, kd, filename="sguard.dat"):
    with open(filename, 'w', encoding='utf-8') as file:
        for idx, word in enumerate(words):
            word_index = BIP39_WORDLIST.index(word) + 1
            file.write(f"{str(idx + 1).zfill(2)} {str(word_index).zfill(4)} {word}\n")
        file.write(f"KD = {kd}\n")

# Try to fix an invalid mnemonic by modifying the 24th word incrementally
# Returns corrected mnemonic and offset if successful, else None
def fix_mnemonic(words):
    original_last_word_index = BIP39_WORDLIST.index(words[-1])

    for i in range(1, len(BIP39_WORDLIST)):
        new_index = (original_last_word_index + i) % len(BIP39_WORDLIST)
        words[-1] = BIP39_WORDLIST[new_index]
        if mnemonic_to_entropy(words):
            return words, i

    return None, None

# Main program flow
def main():
    load_bip39_wordlist()
    words = read_sguard_file()
    if not words:
        return

    if mnemonic_to_entropy(words):
        print("Mnemonic phrase is valid.")
        return

    new_words, kd = fix_mnemonic(words)
    if new_words:
        write_sguard_file(new_words, kd)
        print(f"Mnemonic corrected. Offset KD = {kd}.")
    else:
        print("Error: unable to correct mnemonic.")

if __name__ == '__main__':
    main()
