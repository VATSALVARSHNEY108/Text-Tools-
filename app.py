import streamlit as st
import base64
import hashlib
import urllib.parse
import re
import random
import string
import binascii
import html
import json
import uuid
import qrcode
from io import BytesIO
from PIL import Image
import textwrap

# Initialize session state
if 'selected_category' not in st.session_state:
    st.session_state.selected_category = None


def main_page():
    """Display the main category selection page"""
    st.title("🛠️ Text Processing Tools")
    st.markdown("### Select a category to access tools")

    # Create a grid layout for categories
    categories = [
        {"name": "Text Conversion Tools", "icon": "🔄", "description": "Convert between formats"},
        {"name": "Text Formatting & Cleaning Tools", "icon": "🧹", "description": "Clean and format text"},
        {"name": "Text Analysis Tools", "icon": "📊", "description": "Analyze text properties"},
        {"name": "Encoding & Encryption Tools", "icon": "🔐", "description": "Encode and encrypt"},
        {"name": "Text Generation Tools", "icon": "✨", "description": "Generate random text"},
        {"name": "Language Tools", "icon": "🌐", "description": "Language utilities"},
        {"name": "Text Extraction Tools", "icon": "📝", "description": "Extract text patterns"},
        {"name": "Text Editing Utilities", "icon": "✂️", "description": "Edit and modify text"},
        {"name": "Text Styling Tools", "icon": "🎨", "description": "Style and format"},
        {"name": "Miscellaneous", "icon": "🔧", "description": "Other useful tools"}
    ]

    # Create 2 columns for grid layout
    cols = st.columns(2)

    for i, category in enumerate(categories):
        col = cols[i % 2]
        with col:
            if st.button(
                    f"{category['icon']} {category['name']}\n{category['description']}",
                    key=f"cat_{i}",
                    use_container_width=True
            ):
                st.session_state.selected_category = category['name']
                st.rerun()


def text_conversion_tools():
    """Text Conversion Tools category"""
    st.title("🔄 Text Conversion Tools")

    tool = st.selectbox("Select Tool:", [
        "Text to Binary / Binary to Text",
        "Text to ASCII / ASCII to Text",
        "Text to Unicode (Unicode escape, UTF-8, UTF-16, ASCII)",
        "Text to Hex / Hex to Text",
        "Text to HTML Entities / Decode HTML Entities",
        "Text to Base64 / Base64 to Text",
        "Text to Numbers / ASCII Code to Text",
        "Text to QR Code",
        "Transliteration Tools (e.g., Hindi to English script)"
    ])

    st.divider()

    if tool == "Text to Binary / Binary to Text":
        col1, col2 = st.columns(2)
        with col1:
            st.subheader("Text to Binary")
            text_input = st.text_area("Enter text:", key="text_to_binary")
            if text_input:
                binary = ' '.join(format(ord(char), '08b') for char in text_input)
                st.text_area("Binary output:", binary, height=100)

        with col2:
            st.subheader("Binary to Text")
            binary_input = st.text_area("Enter binary:", key="binary_to_text")
            if binary_input:
                try:
                    binary_clean = binary_input.replace(' ', '')
                    if len(binary_clean) % 8 == 0:
                        text = ''.join(chr(int(binary_clean[i:i + 8], 2)) for i in range(0, len(binary_clean), 8))
                        st.text_area("Text output:", text, height=100)
                    else:
                        st.error("Binary length must be multiple of 8")
                except:
                    st.error("Invalid binary format")

    elif tool == "Text to ASCII / ASCII to Text":
        col1, col2 = st.columns(2)
        with col1:
            st.subheader("Text to ASCII")
            text_input = st.text_area("Enter text:", key="text_to_ascii")
            if text_input:
                ascii_codes = ' '.join(str(ord(char)) for char in text_input)
                st.text_area("ASCII codes:", ascii_codes, height=100)

        with col2:
            st.subheader("ASCII to Text")
            ascii_input = st.text_area("Enter ASCII codes (space separated):", key="ascii_to_text")
            if ascii_input:
                try:
                    codes = ascii_input.split()
                    text = ''.join(chr(int(code)) for code in codes)
                    st.text_area("Text output:", text, height=100)
                except:
                    st.error("Invalid ASCII codes")

    elif tool == "Text to Hex / Hex to Text":
        col1, col2 = st.columns(2)
        with col1:
            st.subheader("Text to Hex")
            text_input = st.text_area("Enter text:", key="text_to_hex")
            if text_input:
                hex_output = text_input.encode('utf-8').hex()
                st.text_area("Hex output:", hex_output, height=100)

        with col2:
            st.subheader("Hex to Text")
            hex_input = st.text_area("Enter hex:", key="hex_to_text")
            if hex_input:
                try:
                    text = bytes.fromhex(hex_input.replace(' ', '')).decode('utf-8')
                    st.text_area("Text output:", text, height=100)
                except:
                    st.error("Invalid hex format")

    elif tool == "Text to Base64 / Base64 to Text":
        col1, col2 = st.columns(2)
        with col1:
            st.subheader("Text to Base64")
            text_input = st.text_area("Enter text:", key="text_to_base64")
            if text_input:
                encoded = base64.b64encode(text_input.encode('utf-8')).decode('utf-8')
                st.text_area("Base64 output:", encoded, height=100)

        with col2:
            st.subheader("Base64 to Text")
            base64_input = st.text_area("Enter Base64:", key="base64_to_text")
            if base64_input:
                try:
                    decoded = base64.b64decode(base64_input).decode('utf-8')
                    st.text_area("Text output:", decoded, height=100)
                except:
                    st.error("Invalid Base64 format")

    elif tool == "Text to HTML Entities / Decode HTML Entities":
        col1, col2 = st.columns(2)
        with col1:
            st.subheader("Text to HTML Entities")
            text_input = st.text_area("Enter text:", key="text_to_html")
            if text_input:
                encoded = html.escape(text_input)
                st.text_area("HTML entities:", encoded, height=100)

        with col2:
            st.subheader("Decode HTML Entities")
            html_input = st.text_area("Enter HTML entities:", key="html_to_text")
            if html_input:
                decoded = html.unescape(html_input)
                st.text_area("Decoded text:", decoded, height=100)

    elif tool == "Text to Unicode (Unicode escape, UTF-8, UTF-16, ASCII)":
        col1, col2 = st.columns(2)
        with col1:
            st.subheader("Text to Unicode")
            text_input = st.text_area("Enter text:", key="text_to_unicode")
            if text_input:
                # Unicode escape sequences
                unicode_escape = repr(text_input)[1:-1]
                st.text_area("Unicode escape:", unicode_escape, height=100)

                # UTF-8 bytes
                utf8_bytes = ' '.join([f'\\x{b:02x}' for b in text_input.encode('utf-8')])
                st.text_area("UTF-8 bytes:", utf8_bytes, height=100)

                # UTF-16 bytes
                utf16_bytes = ' '.join([f'\\x{b:02x}' for b in text_input.encode('utf-16')])
                st.text_area("UTF-16 bytes:", utf16_bytes, height=100)

        with col2:
            st.subheader("Unicode to Text")
            unicode_input = st.text_area("Enter Unicode escape:", key="unicode_to_text")
            if unicode_input:
                try:
                    # Try to decode unicode escape
                    decoded = unicode_input.encode().decode('unicode_escape')
                    st.text_area("Decoded text:", decoded, height=100)
                except:
                    st.error("Invalid Unicode format")

    elif tool == "Text to Numbers / ASCII Code to Text":
        col1, col2 = st.columns(2)
        with col1:
            st.subheader("Text to ASCII Numbers")
            text_input = st.text_area("Enter text:", key="text_to_numbers")
            if text_input:
                ascii_numbers = ' '.join(str(ord(char)) for char in text_input)
                st.text_area("ASCII numbers:", ascii_numbers, height=100)

        with col2:
            st.subheader("ASCII Numbers to Text")
            numbers_input = st.text_area("Enter ASCII numbers (space separated):", key="numbers_to_text")
            if numbers_input:
                try:
                    numbers = numbers_input.split()
                    text = ''.join(chr(int(num)) for num in numbers)
                    st.text_area("Text output:", text, height=100)
                except:
                    st.error("Invalid ASCII numbers")

    elif tool == "Transliteration Tools (e.g., Hindi to English script)":
        st.subheader("Transliteration Tools")
        text_input = st.text_area("Enter text to transliterate:")

        transliteration_type = st.selectbox("Transliteration type:", [
            "Hindi to English (Devanagari to Roman)",
            "Russian to English (Cyrillic to Roman)",
            "Greek to English"
        ])

        if text_input:
            if transliteration_type == "Hindi to English (Devanagari to Roman)":
                # Basic Hindi to English transliteration mapping
                hindi_to_english = {
                    'अ': 'a', 'आ': 'aa', 'इ': 'i', 'ई': 'ee', 'उ': 'u', 'ऊ': 'oo',
                    'ए': 'e', 'ऐ': 'ai', 'ओ': 'o', 'औ': 'au',
                    'क': 'ka', 'ख': 'kha', 'ग': 'ga', 'घ': 'gha',
                    'च': 'cha', 'छ': 'chha', 'ज': 'ja', 'झ': 'jha',
                    'त': 'ta', 'थ': 'tha', 'द': 'da', 'ध': 'dha', 'न': 'na',
                    'प': 'pa', 'फ': 'pha', 'ब': 'ba', 'भ': 'bha', 'म': 'ma',
                    'य': 'ya', 'र': 'ra', 'ल': 'la', 'व': 'va',
                    'श': 'sha', 'ष': 'shha', 'स': 'sa', 'ह': 'ha'
                }

                result = ""
                for char in text_input:
                    result += hindi_to_english.get(char, char)

            elif transliteration_type == "Russian to English (Cyrillic to Roman)":
                # Basic Russian to English transliteration
                cyrillic_to_roman = {
                    'а': 'a', 'б': 'b', 'в': 'v', 'г': 'g', 'д': 'd', 'е': 'e',
                    'ё': 'yo', 'ж': 'zh', 'з': 'z', 'и': 'i', 'й': 'y', 'к': 'k',
                    'л': 'l', 'м': 'm', 'н': 'n', 'о': 'o', 'п': 'p', 'р': 'r',
                    'с': 's', 'т': 't', 'у': 'u', 'ф': 'f', 'х': 'kh', 'ц': 'ts',
                    'ч': 'ch', 'ш': 'sh', 'щ': 'shch', 'ъ': '', 'ы': 'y', 'ь': '',
                    'э': 'e', 'ю': 'yu', 'я': 'ya',
                    'А': 'A', 'Б': 'B', 'В': 'V', 'Г': 'G', 'Д': 'D', 'Е': 'E',
                    'Ё': 'Yo', 'Ж': 'Zh', 'З': 'Z', 'И': 'I', 'Й': 'Y', 'К': 'K',
                    'Л': 'L', 'М': 'M', 'Н': 'N', 'О': 'O', 'П': 'P', 'Р': 'R',
                    'С': 'S', 'Т': 'T', 'У': 'U', 'Ф': 'F', 'Х': 'Kh', 'Ц': 'Ts',
                    'Ч': 'Ch', 'Ш': 'Sh', 'Щ': 'Shch', 'Ъ': '', 'Ы': 'Y', 'Ь': '',
                    'Э': 'E', 'Ю': 'Yu', 'Я': 'Ya'
                }

                result = ""
                for char in text_input:
                    result += cyrillic_to_roman.get(char, char)

            elif transliteration_type == "Greek to English":
                # Basic Greek to English transliteration
                greek_to_english = {
                    'α': 'a', 'β': 'b', 'γ': 'g', 'δ': 'd', 'ε': 'e', 'ζ': 'z',
                    'η': 'e', 'θ': 'th', 'ι': 'i', 'κ': 'k', 'λ': 'l', 'μ': 'm',
                    'ν': 'n', 'ξ': 'x', 'ο': 'o', 'π': 'p', 'ρ': 'r', 'σ': 's',
                    'τ': 't', 'υ': 'y', 'φ': 'f', 'χ': 'ch', 'ψ': 'ps', 'ω': 'o',
                    'Α': 'A', 'Β': 'B', 'Γ': 'G', 'Δ': 'D', 'Ε': 'E', 'Ζ': 'Z',
                    'Η': 'E', 'Θ': 'Th', 'Ι': 'I', 'Κ': 'K', 'Λ': 'L', 'Μ': 'M',
                    'Ν': 'N', 'Ξ': 'X', 'Ο': 'O', 'Π': 'P', 'Ρ': 'R', 'Σ': 'S',
                    'Τ': 'T', 'Υ': 'Y', 'Φ': 'F', 'Χ': 'Ch', 'Ψ': 'Ps', 'Ω': 'O'
                }

                result = ""
                for char in text_input:
                    result += greek_to_english.get(char, char)

            st.text_area("Transliterated text:", result, height=100)

    elif tool == "Text to QR Code":
        st.subheader("Text to QR Code")
        text_input = st.text_area("Enter text for QR code:")
        if text_input:
            qr = qrcode.QRCode(version=1, box_size=10, border=5)
            qr.add_data(text_input)
            qr.make(fit=True)
            img = qr.make_image(fill_color="black", back_color="white")
            # Convert PIL image to bytes for Streamlit
            img_buffer = BytesIO()
            img.save(img_buffer, format='PNG')
            st.image(img_buffer.getvalue(), caption="QR Code")


def text_formatting_tools():
    """Text Formatting & Cleaning Tools category"""
    st.title("🧹 Text Formatting & Cleaning Tools")

    tool = st.selectbox("Select Tool:", [
        "Remove Extra Spaces",
        "Remove Line Breaks",
        "Remove Empty Lines",
        "Remove Special Characters",
        "Keep Only Special Characters",
        "Text Capitalization",
        "Text Indentation & Alignment",
        "Text Reverse (Reverse Text, Words, or Sentences)",
        "Sort Lines Alphabetically",
        "Randomize Lines or Words",
        "Trim Text (Left, Right, Both Whitespace/Characters)"
    ])

    st.divider()
    text_input = st.text_area("Enter text:", height=150)

    if text_input:
        if tool == "Remove Extra Spaces":
            result = re.sub(r'\s+', ' ', text_input).strip()
        elif tool == "Remove Line Breaks":
            result = text_input.replace('\n', ' ').replace('\r', '')
        elif tool == "Remove Empty Lines":
            lines = text_input.split('\n')
            result = '\n'.join(line for line in lines if line.strip())
        elif tool == "Remove Special Characters":
            result = re.sub(r'[^a-zA-Z0-9\s]', '', text_input)
        elif tool == "Keep Only Special Characters":
            result = re.sub(r'[a-zA-Z0-9\s]', '', text_input)
        elif tool == "Text Capitalization":
            cap_type = st.selectbox("Capitalization type:", ["UPPER CASE", "lower case", "Title Case", "Sentence case"])
            if cap_type == "UPPER CASE":
                result = text_input.upper()
            elif cap_type == "lower case":
                result = text_input.lower()
            elif cap_type == "Title Case":
                result = text_input.title()
            else:  # Sentence case
                result = '. '.join(sentence.strip().capitalize() for sentence in text_input.split('.'))
        elif tool == "Text Reverse":
            reverse_type = st.selectbox("Reverse type:", ["Reverse Text", "Reverse Words", "Reverse Sentences"])
            if reverse_type == "Reverse Text":
                result = text_input[::-1]
            elif reverse_type == "Reverse Words":
                result = ' '.join(text_input.split()[::-1])
            else:  # Reverse Sentences
                result = '. '.join(text_input.split('.')[::-1])
        elif tool == "Sort Lines Alphabetically":
            lines = text_input.split('\n')
            result = '\n'.join(sorted(lines))
        elif tool == "Randomize Lines or Words":
            random_type = st.selectbox("Randomize type:", ["Lines", "Words"])
            if random_type == "Lines":
                lines = text_input.split('\n')
                random.shuffle(lines)
                result = '\n'.join(lines)
            else:  # Words
                words = text_input.split()
                random.shuffle(words)
                result = ' '.join(words)
        else:  # Trim Text
            trim_type = st.selectbox("Trim type:", ["Both", "Left", "Right"])
            if trim_type == "Both":
                result = text_input.strip()
            elif trim_type == "Left":
                result = text_input.lstrip()
            else:  # Right
                result = text_input.rstrip()

        st.text_area("Result:", result, height=150)


def text_analysis_tools():
    """Text Analysis Tools category"""
    st.title("📊 Text Analysis Tools")

    tool = st.selectbox("Select Tool:", [
        "Word Counter",
        "Character Counter",
        "Line Counter",
        "Keyword Density Analyzer",
        "Readability Score Calculator",
        "Find Duplicate Lines",
        "N-Gram Generator",
        "Plagiarism Checker (Basic API based)",
        "Text Similarity Calculator"
    ])

    st.divider()
    text_input = st.text_area("Enter text:", height=150)

    if text_input:
        if tool == "Word Counter":
            words = text_input.split()
            word_count = len(words)
            unique_words = len(set(word.lower().strip('.,!?;:"()[]{}') for word in words))

            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Total Words", word_count)
            with col2:
                st.metric("Unique Words", unique_words)
            with col3:
                st.metric("Average Word Length",
                          f"{sum(len(word) for word in words) / len(words):.1f}" if words else "0")

        elif tool == "Character Counter":
            char_count = len(text_input)
            char_no_spaces = len(text_input.replace(' ', ''))
            line_count = len(text_input.split('\n'))

            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Total Characters", char_count)
            with col2:
                st.metric("Characters (no spaces)", char_no_spaces)
            with col3:
                st.metric("Lines", line_count)

        elif tool == "Line Counter":
            lines = text_input.split('\n')
            total_lines = len(lines)
            non_empty_lines = len([line for line in lines if line.strip()])
            empty_lines = total_lines - non_empty_lines

            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Total Lines", total_lines)
            with col2:
                st.metric("Non-empty Lines", non_empty_lines)
            with col3:
                st.metric("Empty Lines", empty_lines)

        elif tool == "Keyword Density Analyzer":
            words = re.findall(r'\b\w+\b', text_input.lower())
            word_freq = {}
            for word in words:
                word_freq[word] = word_freq.get(word, 0) + 1

            total_words = len(words)
            if total_words > 0:
                st.subheader("Top 10 Most Frequent Words")
                sorted_words = sorted(word_freq.items(), key=lambda x: x[1], reverse=True)[:10]
                for word, count in sorted_words:
                    density = (count / total_words) * 100
                    st.write(f"**{word}**: {count} times ({density:.1f}%)")

        elif tool == "Find Duplicate Lines":
            lines = text_input.split('\n')
            line_count = {}
            for line in lines:
                if line.strip():
                    line_count[line] = line_count.get(line, 0) + 1

            duplicates = {line: count for line, count in line_count.items() if count > 1}
            if duplicates:
                st.subheader("Duplicate Lines Found:")
                for line, count in duplicates.items():
                    st.write(f"**{count} times**: {line}")
            else:
                st.info("No duplicate lines found.")


def encoding_encryption_tools():
    """Encoding & Encryption Tools category"""
    st.title("🔐 Encoding & Encryption Tools")

    tool = st.selectbox("Select Tool:", [
        "URL Encoder / Decoder",
        "UTF-8 Encoder / Decoder",
        "ROT13 / ROT47 Cipher",
        "SHA / MD5 Hash Generator",
        "Caesar Cipher",
        "Morse Code",
        "Simple Text Encryption (Custom Key)"
    ])

    st.divider()

    if tool == "URL Encoder / Decoder":
        col1, col2 = st.columns(2)
        with col1:
            st.subheader("URL Encoder")
            text_input = st.text_area("Enter text to encode:", key="url_encode")
            if text_input:
                encoded = urllib.parse.quote(text_input)
                st.text_area("Encoded URL:", encoded)

        with col2:
            st.subheader("URL Decoder")
            url_input = st.text_area("Enter URL to decode:", key="url_decode")
            if url_input:
                try:
                    decoded = urllib.parse.unquote(url_input)
                    st.text_area("Decoded text:", decoded)
                except:
                    st.error("Invalid URL format")

    elif tool == "SHA / MD5 Hash Generator":
        text_input = st.text_area("Enter text to hash:")
        if text_input:
            md5_hash = hashlib.md5(text_input.encode()).hexdigest()
            sha1_hash = hashlib.sha1(text_input.encode()).hexdigest()
            sha256_hash = hashlib.sha256(text_input.encode()).hexdigest()

            st.subheader("Hash Results:")
            st.text_input("MD5:", md5_hash)
            st.text_input("SHA1:", sha1_hash)
            st.text_input("SHA256:", sha256_hash)

    elif tool == "ROT13 / ROT47 Cipher":
        cipher_type = st.selectbox("Cipher type:", ["ROT13", "ROT47"])
        text_input = st.text_area("Enter text:")

        if text_input:
            if cipher_type == "ROT13":
                result = ""
                for char in text_input:
                    if 'a' <= char <= 'z':
                        result += chr((ord(char) - ord('a') + 13) % 26 + ord('a'))
                    elif 'A' <= char <= 'Z':
                        result += chr((ord(char) - ord('A') + 13) % 26 + ord('A'))
                    else:
                        result += char
            else:  # ROT47
                result = ""
                for char in text_input:
                    if 33 <= ord(char) <= 126:
                        result += chr((ord(char) - 33 + 47) % 94 + 33)
                    else:
                        result += char

            st.text_area("Result:", result)

    elif tool == "Caesar Cipher":
        shift = st.number_input("Shift value:", min_value=1, max_value=25, value=3)
        operation = st.selectbox("Operation:", ["Encrypt", "Decrypt"])
        text_input = st.text_area("Enter text:")

        if text_input:
            shift_val = shift if operation == "Encrypt" else -shift
            result = ""
            for char in text_input:
                if 'a' <= char <= 'z':
                    result += chr((ord(char) - ord('a') + shift_val) % 26 + ord('a'))
                elif 'A' <= char <= 'Z':
                    result += chr((ord(char) - ord('A') + shift_val) % 26 + ord('A'))
                else:
                    result += char

            st.text_area("Result:", result)

    elif tool == "Morse Code":
        morse_dict = {
            'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.',
            'G': '--.', 'H': '....', 'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..',
            'M': '--', 'N': '-.', 'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.',
            'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-',
            'Y': '-.--', 'Z': '--..', '0': '-----', '1': '.----', '2': '..---',
            '3': '...--', '4': '....-', '5': '.....', '6': '-....', '7': '--...',
            '8': '---..', '9': '----.', ' ': '/'
        }
        reverse_morse = {v: k for k, v in morse_dict.items()}

        col1, col2 = st.columns(2)
        with col1:
            st.subheader("Text to Morse")
            text_input = st.text_area("Enter text:", key="text_to_morse")
            if text_input:
                morse = ' '.join(morse_dict.get(char.upper(), char) for char in text_input)
                st.text_area("Morse code:", morse)

        with col2:
            st.subheader("Morse to Text")
            morse_input = st.text_area("Enter morse code:", key="morse_to_text")
            if morse_input:
                try:
                    words = morse_input.split(' / ')
                    text = ''
                    for word in words:
                        letters = word.split(' ')
                        for letter in letters:
                            text += reverse_morse.get(letter, letter)
                        text += ' '
                    st.text_area("Decoded text:", text.strip())
                except:
                    st.error("Invalid morse code format")


def text_generation_tools():
    """Text Generation Tools category"""
    st.title("✨ Text Generation Tools")

    tool = st.selectbox("Select Tool:", [
        "Random Word Generator",
        "Random Sentence Generator",
        "Lorem Ipsum Generator",
        "Dummy Text Generator (with custom length)",
        "Random Password Generator",
        "Random Username Generator",
        "Poetry Generator (AI based)",
        "Random Email Generator"
    ])

    st.divider()

    if tool == "Random Word Generator":
        count = st.number_input("Number of words:", min_value=1, max_value=100, value=10)
        word_length = st.slider("Word length:", min_value=3, max_value=15, value=(5, 10))

        if st.button("Generate Words"):
            words = []
            for _ in range(count):
                length = random.randint(word_length[0], word_length[1])
                word = ''.join(random.choices(string.ascii_lowercase, k=length))
                words.append(word)
            st.text_area("Generated words:", ' '.join(words))

    elif tool == "Random Sentence Generator":
        count = st.number_input("Number of sentences:", min_value=1, max_value=20, value=5)

        if st.button("Generate Sentences"):
            sentence_starters = ["The", "A", "An", "This", "That", "Every", "Some", "Many"]
            verbs = ["runs", "jumps", "walks", "thinks", "creates", "builds", "discovers", "explores"]
            objects = ["quickly", "slowly", "carefully", "eagerly", "quietly", "boldly", "gracefully"]

            sentences = []
            for _ in range(count):
                starter = random.choice(sentence_starters)
                verb = random.choice(verbs)
                obj = random.choice(objects)
                sentence = f"{starter} person {verb} {obj}."
                sentences.append(sentence)

            st.text_area("Generated sentences:", ' '.join(sentences))

    elif tool == "Lorem Ipsum Generator":
        paragraph_count = st.number_input("Number of paragraphs:", min_value=1, max_value=10, value=3)

        lorem_words = ["lorem", "ipsum", "dolor", "sit", "amet", "consectetur", "adipiscing", "elit",
                       "sed", "do", "eiusmod", "tempor", "incididunt", "ut", "labore", "et", "dolore",
                       "magna", "aliqua", "enim", "ad", "minim", "veniam", "quis", "nostrud"]

        if st.button("Generate Lorem Ipsum"):
            paragraphs = []
            for _ in range(paragraph_count):
                sentences = []
                for _ in range(random.randint(3, 7)):
                    sentence_words = random.choices(lorem_words, k=random.randint(8, 15))
                    sentence = ' '.join(sentence_words).capitalize() + '.'
                    sentences.append(sentence)
                paragraphs.append(' '.join(sentences))

            st.text_area("Generated Lorem Ipsum:", '\n\n'.join(paragraphs), height=200)

    elif tool == "Random Password Generator":
        length = st.slider("Password length:", min_value=4, max_value=128, value=12)
        include_upper = st.checkbox("Include uppercase letters", value=True)
        include_lower = st.checkbox("Include lowercase letters", value=True)
        include_numbers = st.checkbox("Include numbers", value=True)
        include_symbols = st.checkbox("Include symbols", value=True)

        if st.button("Generate Password"):
            chars = ""
            if include_upper:
                chars += string.ascii_uppercase
            if include_lower:
                chars += string.ascii_lowercase
            if include_numbers:
                chars += string.digits
            if include_symbols:
                chars += "!@#$%^&*()_+-=[]{}|;:,.<>?"

            if chars:
                password = ''.join(random.choices(chars, k=length))
                st.text_input("Generated password:", password, type="password")
                st.text_input("Password (visible):", password)
            else:
                st.error("Please select at least one character type")

    elif tool == "Dummy Text Generator (with custom length)":
        text_length = st.number_input("Text length (characters):", min_value=10, max_value=5000, value=500)
        text_type = st.selectbox("Text type:", ["Random words", "Lorem Ipsum style", "Technical text"])

        if st.button("Generate Dummy Text"):
            if text_type == "Random words":
                words = []
                current_length = 0
                while current_length < text_length:
                    word_len = random.randint(3, 10)
                    word = ''.join(random.choices(string.ascii_lowercase, k=word_len))
                    if current_length + len(word) + 1 <= text_length:
                        words.append(word)
                        current_length += len(word) + 1
                    else:
                        break
                dummy_text = ' '.join(words)

            elif text_type == "Lorem Ipsum style":
                lorem_words = ["lorem", "ipsum", "dolor", "sit", "amet", "consectetur", "adipiscing", "elit",
                               "sed", "do", "eiusmod", "tempor", "incididunt", "ut", "labore", "et", "dolore",
                               "magna", "aliqua", "enim", "ad", "minim", "veniam", "quis", "nostrud", "exercitation",
                               "ullamco", "laboris", "nisi", "aliquip", "ex", "ea", "commodo", "consequat"]
                words = []
                current_length = 0
                while current_length < text_length:
                    word = random.choice(lorem_words)
                    if current_length + len(word) + 1 <= text_length:
                        words.append(word)
                        current_length += len(word) + 1
                    else:
                        break
                dummy_text = ' '.join(words)

            else:  # Technical text
                tech_words = ["algorithm", "database", "function", "variable", "array", "object", "class",
                              "method", "parameter", "return", "loop", "condition", "boolean", "string",
                              "integer", "float", "exception", "module", "import", "export", "interface",
                              "protocol", "server", "client", "request", "response", "authentication"]
                words = []
                current_length = 0
                while current_length < text_length:
                    word = random.choice(tech_words)
                    if current_length + len(word) + 1 <= text_length:
                        words.append(word)
                        current_length += len(word) + 1
                    else:
                        break
                dummy_text = ' '.join(words)

            st.text_area("Generated dummy text:", dummy_text, height=200)
            st.info(f"Generated {len(dummy_text)} characters")

    elif tool == "Random Username Generator":
        count = st.number_input("Number of usernames:", min_value=1, max_value=50, value=10)
        username_style = st.selectbox("Username style:", ["Simple", "With numbers", "With underscores", "Mixed"])

        if st.button("Generate Usernames"):
            adjectives = ["happy", "smart", "quick", "bright", "cool", "fast", "strong", "clever",
                          "awesome", "super", "mega", "ultra", "epic", "pro", "ace", "ninja"]
            nouns = ["tiger", "eagle", "wolf", "lion", "dragon", "phoenix", "hawk", "panther",
                     "warrior", "hero", "legend", "master", "champion", "star", "rocket", "thunder"]

            usernames = []
            for _ in range(count):
                adj = random.choice(adjectives)
                noun = random.choice(nouns)

                if username_style == "Simple":
                    username = f"{adj}{noun}"
                elif username_style == "With numbers":
                    num = random.randint(1, 999)
                    username = f"{adj}{noun}{num}"
                elif username_style == "With underscores":
                    username = f"{adj}_{noun}"
                else:  # Mixed
                    separator = random.choice(["", "_", ""])
                    num = random.randint(1, 99) if random.choice([True, False]) else ""
                    username = f"{adj}{separator}{noun}{num}"

                usernames.append(username)

            st.text_area("Generated usernames:", '\n'.join(usernames), height=200)

    elif tool == "Poetry Generator (AI based)":
        poem_style = st.selectbox("Poem style:", ["Haiku", "Limerick", "Free verse", "Rhyming couplets"])
        theme = st.text_input("Theme/Topic (optional):", placeholder="e.g., nature, love, technology")

        if st.button("Generate Poem"):
            if poem_style == "Haiku":
                # Simple haiku generator with 5-7-5 syllable pattern
                nature_words = ["cherry", "river", "mountain", "sunset", "moonlight", "forest", "ocean", "flower"]
                feelings = ["peaceful", "gentle", "serene", "quiet", "flowing", "bright", "soft", "calm"]
                actions = ["whispers", "flows", "dances", "shines", "blooms", "falls", "rises", "sings"]

                line1 = f"{random.choice(nature_words).title()} {random.choice(actions)} gently"  # 5 syllables approx
                line2 = f"In the {random.choice(['morning', 'evening', 'distant'])} {random.choice(nature_words)} light"  # 7 syllables approx
                line3 = f"{random.choice(feelings).title()} silence"  # 5 syllables approx

                poem = f"{line1}\n{line2}\n{line3}"

            elif poem_style == "Limerick":
                names = ["Mary", "Peter", "Sally", "John", "Kate", "Tom", "Jane", "Bob"]
                places = ["France", "Spain", "Maine", "the park", "the store", "the zoo"]
                adjectives = ["funny", "clever", "silly", "happy", "crazy", "witty"]
                actions = ["danced", "sang", "laughed", "jumped", "smiled", "played"]

                name = random.choice(names)
                place = random.choice(places)
                adj = random.choice(adjectives)
                action = random.choice(actions)

                poem = f"There once was a person named {name}\nWho lived in a place called {place}\nThey were quite {adj}\nAnd {action} every day\nAnd brought joy to all in {place}"

            elif poem_style == "Free verse":
                if theme:
                    poem = f"Thoughts of {theme}\nFlow like water through my mind\nShaping moments\nInto memories\n\nEach word\nA stepping stone\nAcross the river\nOf consciousness"
                else:
                    poem = "Words dance\nOn the edge of silence\nMeaning waits\nIn the spaces between\n\nLife unfolds\nLike paper cranes\nDelicate and purposeful\nIn their simplicity"

            else:  # Rhyming couplets
                if theme and "nature" in theme.lower():
                    poem = "The trees sway gently in the breeze so light\nTheir leaves shimmer golden in the fading light\n\nThe river flows with songs of ancient lore\nWhile birds sing melodies from shore to shore"
                else:
                    poem = "Dreams take flight on wings of hope so bright\nGuiding us through darkness into light\n\nWith every step we take along the way\nWe write the story of another day"

            st.text_area("Generated poem:", poem, height=200)

    elif tool == "Random Email Generator":
        count = st.number_input("Number of emails:", min_value=1, max_value=50, value=10)
        domain_type = st.selectbox("Domain type:", ["Popular domains", "Custom domain", "Business domains"])

        if domain_type == "Custom domain":
            custom_domain = st.text_input("Enter custom domain:", placeholder="example.com")

        if st.button("Generate Emails"):
            first_names = ["john", "jane", "mike", "sarah", "alex", "lisa", "david", "emma",
                           "chris", "anna", "mark", "lucy", "tom", "sophie", "james", "kate"]
            last_names = ["smith", "johnson", "brown", "davis", "miller", "wilson", "moore",
                          "taylor", "anderson", "thomas", "jackson", "white", "harris", "martin"]

            if domain_type == "Popular domains":
                domains = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "icloud.com"]
            elif domain_type == "Custom domain" and custom_domain:
                domains = [custom_domain]
            elif domain_type == "Custom domain":
                domains = ["example.com"]
            else:  # Business domains
                domains = ["company.com", "business.org", "enterprise.net", "corp.com", "firm.biz"]

            emails = []
            for _ in range(count):
                first = random.choice(first_names)
                last = random.choice(last_names)
                domain = random.choice(domains)

                # Different email format styles
                format_style = random.choice([
                    f"{first}.{last}@{domain}",
                    f"{first}{last}@{domain}",
                    f"{first}_{last}@{domain}",
                    f"{first}{random.randint(1, 999)}@{domain}",
                    f"{first[0]}{last}@{domain}"
                ])

                emails.append(format_style)

            st.text_area("Generated emails:", '\n'.join(emails), height=200)


def language_tools():
    """Language Tools category"""
    st.title("🌐 Language Tools")

    tool = st.selectbox("Select Tool:", [
        "Text Translation (API based)",
        "Spell Checker",
        "Grammar Checker",
        "Synonym & Antonym Finder",
        "Language Detection",
        "Phonetic Converter",
        "Acronym & Abbreviation Expander"
    ])

    st.divider()
    text_input = st.text_area("Enter text:", height=100)

    if tool == "Spell Checker":
        if text_input:
            # Basic spell checker simulation
            common_words = set(
                ['the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 'of', 'with', 'by', 'is', 'are',
                 'was', 'were', 'be', 'been', 'being', 'have', 'has', 'had', 'do', 'does', 'did', 'will', 'would',
                 'could', 'should', 'may', 'might', 'can', 'must', 'this', 'that', 'these', 'those', 'i', 'you', 'he',
                 'she', 'it', 'we', 'they', 'me', 'him', 'her', 'us', 'them', 'my', 'your', 'his', 'our', 'their',
                 'mine', 'yours', 'ours', 'theirs', 'myself', 'yourself', 'himself', 'herself', 'itself', 'ourselves',
                 'yourselves', 'themselves'])

            words = re.findall(r'\b\w+\b', text_input.lower())
            potential_errors = [word for word in words if word not in common_words and len(word) > 2]

            if potential_errors:
                st.warning(f"Potential spelling errors: {', '.join(set(potential_errors))}")
            else:
                st.success("No obvious spelling errors found!")

    elif tool == "Language Detection":
        if text_input:
            # Simple language detection based on character patterns
            if re.search(r'[а-яё]', text_input.lower()):
                st.info("Detected language: Russian")
            elif re.search(r'[àáâãäåæçèéêëìíîïðñòóôõöøùúûüýþÿ]', text_input.lower()):
                st.info("Detected language: Romance language (French/Spanish/Italian)")
            elif re.search(r'[äöüß]', text_input.lower()):
                st.info("Detected language: German")
            elif re.search(r'[一-龯]', text_input):
                st.info("Detected language: Chinese")
            elif re.search(r'[ひらがなカタカナ]', text_input):
                st.info("Detected language: Japanese")
            else:
                st.info("Detected language: English (or similar)")

    elif tool == "Text Translation (API based)":
        if text_input:
            target_language = st.selectbox("Translate to:", [
                "Spanish", "French", "German", "Italian", "Portuguese", "Russian",
                "Chinese", "Japanese", "Korean", "Arabic", "Hindi"
            ])

            # Basic word-level translation simulation
            basic_translations = {
                "Spanish": {"hello": "hola", "world": "mundo", "good": "bueno", "bad": "malo",
                            "yes": "sí", "no": "no", "please": "por favor", "thank": "gracias"},
                "French": {"hello": "bonjour", "world": "monde", "good": "bon", "bad": "mauvais",
                           "yes": "oui", "no": "non", "please": "s'il vous plaît", "thank": "merci"},
                "German": {"hello": "hallo", "world": "welt", "good": "gut", "bad": "schlecht",
                           "yes": "ja", "no": "nein", "please": "bitte", "thank": "danke"},
                "Italian": {"hello": "ciao", "world": "mondo", "good": "buono", "bad": "cattivo",
                            "yes": "sì", "no": "no", "please": "per favore", "thank": "grazie"}
            }

            if target_language in basic_translations:
                words = text_input.lower().split()
                translated_words = []
                for word in words:
                    clean_word = re.sub(r'[^\w]', '', word)
                    translated = basic_translations[target_language].get(clean_word, word)
                    translated_words.append(translated)

                result = ' '.join(translated_words)
                st.text_area(f"Translation to {target_language}:", result, height=100)
            else:
                st.info(f"Basic translation to {target_language} not available in demo mode")

    elif tool == "Grammar Checker":
        if text_input:
            # Basic grammar checking
            issues = []

            # Check for double spaces
            if '  ' in text_input:
                issues.append("Double spaces found")

            # Check for sentence capitalization
            sentences = re.split(r'[.!?]+', text_input)
            for sentence in sentences:
                sentence = sentence.strip()
                if sentence and not sentence[0].isupper():
                    issues.append("Sentences should start with capital letters")
                    break

            # Check for missing periods at end
            if text_input.strip() and text_input.strip()[-1] not in '.!?':
                issues.append("Missing punctuation at end of text")

            # Check for repeated words
            words = text_input.lower().split()
            for i in range(len(words) - 1):
                if words[i] == words[i + 1] and len(words[i]) > 2:
                    issues.append(f"Repeated word found: '{words[i]}'")
                    break

            if issues:
                st.warning("Grammar issues found:")
                for issue in issues[:5]:  # Show max 5 issues
                    st.write(f"• {issue}")
            else:
                st.success("No obvious grammar issues found!")

    elif tool == "Synonym & Antonym Finder":
        word_to_check = st.text_input("Enter a word to find synonyms/antonyms:")

        if word_to_check:
            synonyms_dict = {
                "good": ["excellent", "great", "wonderful", "fantastic", "superb", "fine", "nice"],
                "bad": ["terrible", "awful", "horrible", "poor", "dreadful", "lousy", "wicked"],
                "big": ["large", "huge", "enormous", "massive", "giant", "vast", "immense"],
                "small": ["tiny", "little", "minute", "petite", "compact", "miniature", "mini"],
                "happy": ["joyful", "cheerful", "delighted", "pleased", "content", "elated", "ecstatic"],
                "sad": ["unhappy", "sorrowful", "melancholy", "depressed", "gloomy", "miserable", "dejected"],
                "fast": ["quick", "rapid", "speedy", "swift", "hasty", "brisk", "fleet"],
                "slow": ["sluggish", "leisurely", "gradual", "unhurried", "deliberate", "measured", "steady"]
            }

            antonyms_dict = {
                "good": ["bad", "terrible", "awful", "poor", "horrible"],
                "bad": ["good", "excellent", "wonderful", "great", "fantastic"],
                "big": ["small", "tiny", "little", "minute", "petite"],
                "small": ["big", "large", "huge", "enormous", "massive"],
                "happy": ["sad", "unhappy", "sorrowful", "depressed", "miserable"],
                "sad": ["happy", "joyful", "cheerful", "delighted", "pleased"],
                "fast": ["slow", "sluggish", "leisurely", "gradual"],
                "slow": ["fast", "quick", "rapid", "speedy", "swift"]
            }

            word_lower = word_to_check.lower()

            col1, col2 = st.columns(2)

            with col1:
                st.subheader("Synonyms:")
                if word_lower in synonyms_dict:
                    for synonym in synonyms_dict[word_lower]:
                        st.write(f"• {synonym}")
                else:
                    st.info("No synonyms found in database")

            with col2:
                st.subheader("Antonyms:")
                if word_lower in antonyms_dict:
                    for antonym in antonyms_dict[word_lower]:
                        st.write(f"• {antonym}")
                else:
                    st.info("No antonyms found in database")

    elif tool == "Phonetic Converter":
        if text_input:
            # Simple phonetic conversion using basic rules
            phonetic_map = {
                'a': 'ey', 'b': 'bee', 'c': 'see', 'd': 'dee', 'e': 'ee',
                'f': 'eff', 'g': 'jee', 'h': 'aych', 'i': 'eye', 'j': 'jay',
                'k': 'kay', 'l': 'ell', 'm': 'em', 'n': 'en', 'o': 'oh',
                'p': 'pee', 'q': 'cue', 'r': 'are', 's': 'ess', 't': 'tee',
                'u': 'you', 'v': 'vee', 'w': 'double-you', 'x': 'ex', 'y': 'why', 'z': 'zee'
            }

            phonetic_style = st.selectbox("Phonetic style:", ["NATO Alphabet", "Letter Names", "IPA-like"])

            if phonetic_style == "NATO Alphabet":
                nato_alphabet = {
                    'a': 'Alpha', 'b': 'Bravo', 'c': 'Charlie', 'd': 'Delta', 'e': 'Echo',
                    'f': 'Foxtrot', 'g': 'Golf', 'h': 'Hotel', 'i': 'India', 'j': 'Juliet',
                    'k': 'Kilo', 'l': 'Lima', 'm': 'Mike', 'n': 'November', 'o': 'Oscar',
                    'p': 'Papa', 'q': 'Quebec', 'r': 'Romeo', 's': 'Sierra', 't': 'Tango',
                    'u': 'Uniform', 'v': 'Victor', 'w': 'Whiskey', 'x': 'X-ray', 'y': 'Yankee', 'z': 'Zulu'
                }

                result = ""
                for char in text_input.lower():
                    if char.isalpha():
                        result += nato_alphabet.get(char, char) + " "
                    elif char == ' ':
                        result += "/ "
                    else:
                        result += char + " "

                st.text_area("NATO Phonetic:", result.strip(), height=100)

            elif phonetic_style == "Letter Names":
                result = ""
                for char in text_input.lower():
                    if char.isalpha():
                        result += phonetic_map.get(char, char) + " "
                    elif char == ' ':
                        result += "/ "
                    else:
                        result += char + " "

                st.text_area("Letter Names:", result.strip(), height=100)

            else:  # IPA-like
                st.text_area("IPA-like phonetic:", f"/{text_input.lower()}/", height=100)
                st.info("This is a simplified representation. Actual IPA requires specialized linguistic knowledge.")

    elif tool == "Acronym & Abbreviation Expander":
        if text_input:
            # Common acronyms and abbreviations dictionary
            expansions = {
                "AI": "Artificial Intelligence",
                "API": "Application Programming Interface",
                "CEO": "Chief Executive Officer",
                "CTO": "Chief Technology Officer",
                "DNA": "Deoxyribonucleic Acid",
                "FAQ": "Frequently Asked Questions",
                "GPS": "Global Positioning System",
                "HTML": "HyperText Markup Language",
                "HTTP": "HyperText Transfer Protocol",
                "NASA": "National Aeronautics and Space Administration",
                "PDF": "Portable Document Format",
                "RAM": "Random Access Memory",
                "SQL": "Structured Query Language",
                "URL": "Uniform Resource Locator",
                "USB": "Universal Serial Bus",
                "VPN": "Virtual Private Network",
                "WiFi": "Wireless Fidelity",
                "WWW": "World Wide Web",
                "XML": "Extensible Markup Language",
                "etc": "et cetera",
                "i.e.": "id est (that is)",
                "e.g.": "exempli gratia (for example)",
                "vs": "versus",
                "Dr": "Doctor",
                "Mr": "Mister",
                "Mrs": "Missus",
                "Ms": "Miss",
                "Prof": "Professor"
            }

            words = text_input.split()
            expanded_text = text_input
            found_acronyms = []

            for word in words:
                clean_word = word.strip('.,!?;:"()[]{}')
                if clean_word.upper() in expansions:
                    expansion = expansions[clean_word.upper()]
                    found_acronyms.append(f"{clean_word} → {expansion}")

            if found_acronyms:
                st.subheader("Found Acronyms/Abbreviations:")
                for acronym in found_acronyms:
                    st.write(f"• {acronym}")

                # Option to replace in text
                if st.button("Replace in text"):
                    for word in words:
                        clean_word = word.strip('.,!?;:"()[]{}')
                        if clean_word.upper() in expansions:
                            expanded_text = expanded_text.replace(clean_word, expansions[clean_word.upper()])

                    st.text_area("Expanded text:", expanded_text, height=100)
            else:
                st.info("No known acronyms or abbreviations found in the text")


def text_extraction_tools():
    """Text Extraction Tools category"""
    st.title("📝 Text Extraction Tools")

    tool = st.selectbox("Select Tool:", [
        "Extract Email from Text",
        "Extract URL from Text",
        "Extract Numbers from Text",
        "Extract Hashtags from Text"
    ])

    st.divider()
    text_input = st.text_area("Enter text:", height=150)

    if text_input:
        if tool == "Extract Email from Text":
            emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', text_input)
            if emails:
                st.subheader("Extracted Emails:")
                for email in set(emails):
                    st.write(f"• {email}")
            else:
                st.info("No email addresses found")

        elif tool == "Extract URL from Text":
            urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',
                              text_input)
            if urls:
                st.subheader("Extracted URLs:")
                for url in set(urls):
                    st.write(f"• {url}")
            else:
                st.info("No URLs found")

        elif tool == "Extract Numbers from Text":
            numbers = re.findall(r'\b\d+\.?\d*\b', text_input)
            if numbers:
                st.subheader("Extracted Numbers:")
                for number in numbers:
                    st.write(f"• {number}")
            else:
                st.info("No numbers found")

        elif tool == "Extract Hashtags from Text":
            hashtags = re.findall(r'#\w+', text_input)
            if hashtags:
                st.subheader("Extracted Hashtags:")
                for hashtag in set(hashtags):
                    st.write(f"• {hashtag}")
            else:
                st.info("No hashtags found")


def text_editing_utilities():
    """Text Editing Utilities category"""
    st.title("✂️ Text Editing Utilities")

    tool = st.selectbox("Select Tool:", [
        "Markdown to HTML / HTML to Markdown",
        "JSON Formatter & Validator",
        "XML Formatter & Validator",
        "CSV to JSON / JSON to CSV Converter",
        "Text Diff Checker (Compare Two Texts)",
        "Find & Replace",
        "Minify / Beautify Text or Code"
    ])

    st.divider()

    if tool == "JSON Formatter & Validator":
        json_input = st.text_area("Enter JSON:", height=200)
        if json_input:
            try:
                parsed = json.loads(json_input)
                formatted = json.dumps(parsed, indent=2, ensure_ascii=False)
                st.success("✅ Valid JSON")
                st.text_area("Formatted JSON:", formatted, height=200)
            except json.JSONDecodeError as e:
                st.error(f"❌ Invalid JSON: {e}")

    elif tool == "Find & Replace":
        text_input = st.text_area("Enter text:", height=150)
        find_text = st.text_input("Find:")
        replace_text = st.text_input("Replace with:")
        case_sensitive = st.checkbox("Case sensitive", value=True)

        if text_input and find_text:
            if case_sensitive:
                result = text_input.replace(find_text, replace_text)
                count = text_input.count(find_text)
            else:
                result = re.sub(re.escape(find_text), replace_text, text_input, flags=re.IGNORECASE)
                count = len(re.findall(re.escape(find_text), text_input, re.IGNORECASE))

            st.info(f"Replaced {count} occurrence(s)")
            st.text_area("Result:", result, height=150)

    elif tool == "Text Diff Checker (Compare Two Texts)":
        col1, col2 = st.columns(2)
        with col1:
            text1 = st.text_area("Text 1:", height=200, key="diff_text1")
        with col2:
            text2 = st.text_area("Text 2:", height=200, key="diff_text2")

        if text1 and text2:
            lines1 = text1.split('\n')
            lines2 = text2.split('\n')

            st.subheader("Comparison Results:")
            max_lines = max(len(lines1), len(lines2))

            for i in range(max_lines):
                line1 = lines1[i] if i < len(lines1) else ""
                line2 = lines2[i] if i < len(lines2) else ""

                if line1 != line2:
                    st.write(f"**Line {i + 1} differs:**")
                    if line1:
                        st.write(f"Text 1: `{line1}`")
                    if line2:
                        st.write(f"Text 2: `{line2}`")
                    st.write("---")

    elif tool == "Markdown to HTML / HTML to Markdown":
        conversion_type = st.selectbox("Conversion type:", ["Markdown to HTML", "HTML to Markdown"])

        if conversion_type == "Markdown to HTML":
            md_input = st.text_area("Enter Markdown:", height=200)
            if md_input:
                # Basic Markdown to HTML conversion
                html_output = md_input

                # Headers
                html_output = re.sub(r'^### (.*?)$', r'<h3>\1</h3>', html_output, flags=re.MULTILINE)
                html_output = re.sub(r'^## (.*?)$', r'<h2>\1</h2>', html_output, flags=re.MULTILINE)
                html_output = re.sub(r'^# (.*?)$', r'<h1>\1</h1>', html_output, flags=re.MULTILINE)

                # Bold and Italic
                html_output = re.sub(r'\*\*(.*?)\*\*', r'<strong>\1</strong>', html_output)
                html_output = re.sub(r'\*(.*?)\*', r'<em>\1</em>', html_output)

                # Links
                html_output = re.sub(r'\[(.*?)\]\((.*?)\)', r'<a href="\2">\1</a>', html_output)

                # Code blocks
                html_output = re.sub(r'`(.*?)`', r'<code>\1</code>', html_output)

                # Line breaks
                html_output = html_output.replace('\n', '<br>\n')

                st.text_area("HTML Output:", html_output, height=200)

        else:  # HTML to Markdown
            html_input = st.text_area("Enter HTML:", height=200)
            if html_input:
                # Basic HTML to Markdown conversion
                md_output = html_input

                # Headers
                md_output = re.sub(r'<h1>(.*?)</h1>', r'# \1', md_output, flags=re.IGNORECASE)
                md_output = re.sub(r'<h2>(.*?)</h2>', r'## \1', md_output, flags=re.IGNORECASE)
                md_output = re.sub(r'<h3>(.*?)</h3>', r'### \1', md_output, flags=re.IGNORECASE)

                # Bold and Italic
                md_output = re.sub(r'<strong>(.*?)</strong>', r'**\1**', md_output, flags=re.IGNORECASE)
                md_output = re.sub(r'<b>(.*?)</b>', r'**\1**', md_output, flags=re.IGNORECASE)
                md_output = re.sub(r'<em>(.*?)</em>', r'*\1*', md_output, flags=re.IGNORECASE)
                md_output = re.sub(r'<i>(.*?)</i>', r'*\1*', md_output, flags=re.IGNORECASE)

                # Links
                md_output = re.sub(r'<a href="(.*?)">(.*?)</a>', r'[\2](\1)', md_output, flags=re.IGNORECASE)

                # Code
                md_output = re.sub(r'<code>(.*?)</code>', r'`\1`', md_output, flags=re.IGNORECASE)

                # Line breaks
                md_output = re.sub(r'<br\s*/?>', '\n', md_output, flags=re.IGNORECASE)

                # Remove remaining HTML tags
                md_output = re.sub(r'<[^>]+>', '', md_output)

                st.text_area("Markdown Output:", md_output, height=200)

    elif tool == "XML Formatter & Validator":
        xml_input = st.text_area("Enter XML:", height=200)
        if xml_input:
            try:
                # Basic XML validation and formatting
                import xml.dom.minidom as minidom

                # Parse XML
                parsed = minidom.parseString(xml_input)

                # Format with indentation
                formatted_xml = parsed.toprettyxml(indent="  ")

                # Remove empty lines
                lines = [line for line in formatted_xml.split('\n') if line.strip()]
                formatted_xml = '\n'.join(lines)

                st.success("✅ Valid XML")
                st.text_area("Formatted XML:", formatted_xml, height=200)

            except Exception as e:
                st.error(f"❌ Invalid XML: {e}")

    elif tool == "CSV to JSON / JSON to CSV Converter":
        conversion_type = st.selectbox("Conversion type:", ["CSV to JSON", "JSON to CSV"])

        if conversion_type == "CSV to JSON":
            csv_input = st.text_area("Enter CSV data:", height=200)
            if csv_input:
                try:
                    import io
                    import csv

                    # Parse CSV
                    csv_reader = csv.DictReader(io.StringIO(csv_input))
                    data = []
                    for row in csv_reader:
                        data.append(row)

                    # Convert to JSON
                    json_output = json.dumps(data, indent=2, ensure_ascii=False)
                    st.success("✅ CSV converted to JSON")
                    st.text_area("JSON Output:", json_output, height=200)

                except Exception as e:
                    st.error(f"❌ Error converting CSV: {e}")

        else:  # JSON to CSV
            json_input = st.text_area("Enter JSON array:", height=200)
            if json_input:
                try:
                    # Parse JSON
                    data = json.loads(json_input)

                    if isinstance(data, list) and data and isinstance(data[0], dict):
                        import io
                        import csv

                        # Get all unique keys
                        all_keys = set()
                        for item in data:
                            all_keys.update(item.keys())

                        # Create CSV
                        output = io.StringIO()
                        writer = csv.DictWriter(output, fieldnames=sorted(all_keys))
                        writer.writeheader()
                        for row in data:
                            writer.writerow(row)

                        csv_output = output.getvalue()
                        st.success("✅ JSON converted to CSV")
                        st.text_area("CSV Output:", csv_output, height=200)
                    else:
                        st.error("❌ JSON must be an array of objects")

                except json.JSONDecodeError as e:
                    st.error(f"❌ Invalid JSON: {e}")
                except Exception as e:
                    st.error(f"❌ Error converting JSON: {e}")

    elif tool == "Minify / Beautify Text or Code":
        code_type = st.selectbox("Code type:", ["JSON", "CSS", "JavaScript", "HTML", "Plain Text"])
        operation = st.selectbox("Operation:", ["Minify", "Beautify"])
        code_input = st.text_area("Enter code:", height=200)

        if code_input:
            if code_type == "JSON":
                try:
                    parsed = json.loads(code_input)
                    if operation == "Minify":
                        result = json.dumps(parsed, separators=(',', ':'), ensure_ascii=False)
                    else:  # Beautify
                        result = json.dumps(parsed, indent=2, ensure_ascii=False)

                    st.text_area(f"{operation}ed JSON:", result, height=200)
                except json.JSONDecodeError as e:
                    st.error(f"❌ Invalid JSON: {e}")

            elif code_type == "CSS":
                if operation == "Minify":
                    # Basic CSS minification
                    result = re.sub(r'\s+', ' ', code_input)
                    result = re.sub(r';\s*}', '}', result)
                    result = re.sub(r'{\s*', '{', result)
                    result = re.sub(r';\s*', ';', result)
                    result = result.strip()
                else:  # Beautify
                    result = code_input
                    result = re.sub(r'{\s*', ' {\n  ', result)
                    result = re.sub(r';\s*', ';\n  ', result)
                    result = re.sub(r'}\s*', '\n}\n\n', result)
                    result = re.sub(r'\n\s*\n\s*\n', '\n\n', result)

                st.text_area(f"{operation}ed CSS:", result, height=200)

            elif code_type == "JavaScript":
                if operation == "Minify":
                    # Basic JS minification
                    result = re.sub(r'\s+', ' ', code_input)
                    result = re.sub(r';\s*', ';', result)
                    result = result.strip()
                else:  # Beautify
                    result = code_input
                    result = re.sub(r'{\s*', ' {\n  ', result)
                    result = re.sub(r';\s*', ';\n  ', result)
                    result = re.sub(r'}\s*', '\n}\n', result)

                st.text_area(f"{operation}ed JavaScript:", result, height=200)

            elif code_type == "HTML":
                if operation == "Minify":
                    # Basic HTML minification
                    result = re.sub(r'>\s+<', '><', code_input)
                    result = re.sub(r'\s+', ' ', result)
                    result = result.strip()
                else:  # Beautify
                    # Basic HTML beautification
                    result = code_input
                    result = re.sub(r'><', '>\n<', result)
                    lines = result.split('\n')
                    beautified_lines = []
                    indent = 0
                    for line in lines:
                        line = line.strip()
                        if line.startswith('</'):
                            indent -= 1
                        beautified_lines.append('  ' * indent + line)
                        if line.startswith('<') and not line.startswith('</') and not line.endswith('/>'):
                            indent += 1
                    result = '\n'.join(beautified_lines)

                st.text_area(f"{operation}ed HTML:", result, height=200)

            else:  # Plain Text
                if operation == "Minify":
                    result = re.sub(r'\s+', ' ', code_input).strip()
                else:  # Beautify
                    result = '\n'.join(line.strip() for line in code_input.split('\n') if line.strip())

                st.text_area(f"{operation}ed Text:", result, height=200)


def text_styling_tools():
    """Text Styling Tools category"""
    st.title("🎨 Text Styling Tools")

    tool = st.selectbox("Select Tool:", [
        "Fancy Text Generator (Unicode Fonts)",
        "Strikethrough Generator",
        "Zalgo Text Generator",
        "Unicode & Symbol Generator",
        "Subscript Generator",
        "ASCII Art Generator",
        "Kaomoji Generator"
    ])

    st.divider()
    text_input = st.text_input("Enter text:")

    if text_input:
        if tool == "Fancy Text Generator (Unicode Fonts)":
            # Unicode transformations
            styles = {
                "Bold": text_input.translate(
                    str.maketrans('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
                                  '𝐚𝐛𝐜𝐝𝐞𝐟𝐠𝐡𝐢𝐣𝐤𝐥𝐦𝐧𝐨𝐩𝐪𝐫𝐬𝐭𝐮𝐯𝐰𝐱𝐲𝐳𝐀𝐁𝐂𝐃𝐄𝐅𝐆𝐇𝐈𝐉𝐊𝐋𝐌𝐍𝐎𝐏𝐐𝐑𝐒𝐓𝐔𝐕𝐖𝐗𝐘𝐙𝟎𝟏𝟐𝟑𝟒𝟓𝟔𝟕𝟖𝟗')),
                "Italic": text_input.translate(str.maketrans('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ',
                                                             '𝑎𝑏𝑐𝑑𝑒𝑓𝑔ℎ𝑖𝑗𝑘𝑙𝑚𝑛𝑜𝑝𝑞𝑟𝑠𝑡𝑢𝑣𝑤𝑥𝑦𝑧𝐴𝐵𝐶𝐷𝐸𝐹𝐺𝐻𝐼𝐽𝐾𝐿𝑀𝑁𝑂𝑃𝑄𝑅𝑆𝑇𝑈𝑉𝑊𝑋𝑌𝑍')),
                "Script": text_input.translate(str.maketrans('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ',
                                                             '𝒶𝒷𝒸𝒹ℯ𝒻ℊ𝒽𝒾𝒿𝓀𝓁𝓂𝓃ℴ𝓅𝓆𝓇𝓈𝓉𝓊𝓋𝓌𝓍𝓎𝓏𝒜ℬ𝒞𝒟ℰℱ𝒢ℋℐ𝒥𝒦ℒℳ𝒩𝒪𝒫𝒬ℛ𝒮𝒯𝒰𝒱𝒲𝒳𝒴𝒵')),
                "Double-struck": text_input.translate(
                    str.maketrans('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
                                  '𝕒𝕓𝕔𝕕𝕖𝕗𝕘𝕙𝕚𝕛𝕜𝕝𝕞𝕟𝕠𝕡𝕢𝕣𝕤𝕥𝕦𝕧𝕨𝕩𝕪𝕫𝔸𝔹ℂ𝔻𝔼𝔽𝔾ℍ𝕀𝕁𝕂𝕃𝕄ℕ𝕆ℙℚℝ𝕊𝕋𝕌𝕍𝕎𝕏𝕐ℤ𝟘𝟙𝟚𝟛𝟜𝟝𝟞𝟟𝟠𝟡'))
            }

            for style_name, styled_text in styles.items():
                st.text_input(f"{style_name}:", styled_text)

        elif tool == "Strikethrough Generator":
            strikethrough = ''.join(char + '\u0336' for char in text_input)
            st.text_input("Strikethrough:", strikethrough)

        elif tool == "Subscript Generator":
            subscript_map = str.maketrans('0123456789abcdefghijklmnopqrstuvwxyz+-=()',
                                          '₀₁₂₃₄₅₆₇₈₉ₐᵦ_dₑfgₕᵢⱼₖₗₘₙₒₚqᵣₛₜᵤᵥwₓyz₊₋₌₍₎')
            subscript = text_input.translate(subscript_map)
            st.text_input("Subscript:", subscript)

        elif tool == "Zalgo Text Generator":
            zalgo_chars = [
                '\u0300', '\u0301', '\u0302', '\u0303', '\u0304', '\u0305', '\u0306', '\u0307',
                '\u0308', '\u0309', '\u030a', '\u030b', '\u030c', '\u030d', '\u030e', '\u030f',
                '\u0310', '\u0311', '\u0312', '\u0313', '\u0314', '\u0315', '\u0316', '\u0317',
                '\u0318', '\u0319', '\u031a', '\u031b', '\u031c', '\u031d', '\u031e', '\u031f',
                '\u0320', '\u0321', '\u0322', '\u0323', '\u0324', '\u0325', '\u0326', '\u0327',
                '\u0328', '\u0329', '\u032a', '\u032b', '\u032c', '\u032d', '\u032e', '\u032f',
                '\u0330', '\u0331', '\u0332', '\u0333', '\u0334', '\u0335', '\u0336'
            ]

            intensity = st.slider("Zalgo intensity:", min_value=1, max_value=10, value=5)

            zalgo_text = ""
            for char in text_input:
                zalgo_text += char
                for _ in range(random.randint(0, intensity)):
                    zalgo_text += random.choice(zalgo_chars)

            st.text_input("Zalgo text:", zalgo_text)

        elif tool == "Unicode & Symbol Generator":
            symbol_categories = {
                "Mathematical": "∑∏∈∉∋∌∅∆∇∂∫∬∮⊕⊖⊗⊘⊙⊚⊛∝∞≠≡≢≤≥≦≧≨≩≪≫≮≯±×÷√∛∜∴∵∶∷∼∽≈≅≌∣∥⊥∠∡∢⊿",
                "Arrows": "←→↑↓↔↕↖↗↘↙↺↻⇄⇅⇆⇇⇈⇉⇊⇋⇌⇍⇎⇏⇐⇑⇒⇓⇔⇕⇖⇗⇘⇙⇚⇛⇜⇝⇞⇟⇠⇡⇢⇣⇤⇥⇦⇧⇨⇩⇪",
                "Currency": "¢£¤¥₹₽₿€¥₩₪₫₱₵₸₦₡₨₩$¢¤₴₲₪₹₽₿",
                "Stars": "★☆✦✧✩✪✫✬✭✮✯✰✱✲✳✴✵✶✷✸✹✺✻✼✽✾✿❀❁❂❃❄❅❆❇❈❉❊❋",
                "Hearts": "♥♡❤💖💝💘💞💕💗💓💙💚💛💜🖤🤍🤎❣💟💌💋",
                "Geometric": "■□▲△▼▽◆◇○◯◎●◐◑◒◓◔◕◖◗◘◙◚◛◜◝◞◟◠◡◢◣◤◥◦◧◨◩◪◫◬◭◮◯",
                "Music": "♪♫♬♭♮♯𝄞𝄟𝄠𝄡𝄢𝄣𝄤𝄥𝄦𝄧𝄨𝄩𝄪𝄫𝄬𝄭𝄮𝄯𝄰𝄱𝄲𝄳𝄴𝄵𝄶𝄷𝄸𝄹𝄺",
                "Punctuation": "‚„…‰′″‴‵‶‷‸‹›‼‽⁇⁈⁉⁊⁋⁌⁍⁎⁏⁐⁑⁒⁓⁔⁕⁖⁗⁘⁙⁚⁛⁜⁝⁞"
            }

            category = st.selectbox("Symbol category:", list(symbol_categories.keys()))
            symbols = symbol_categories[category]

            st.text_area(f"{category} symbols:", symbols, height=100)
            st.info(f"Click in the text area above and copy the symbols you want to use")

        elif tool == "ASCII Art Generator":
            art_style = st.selectbox("ASCII Art style:", ["Small", "Banner", "Block", "Bubble"])

            if art_style == "Small":
                ascii_art = ""
                for char in text_input.upper():
                    if char == 'A':
                        ascii_art += " █▀█ \n █▀█ \n ▀ █ \n"
                    elif char == 'B':
                        ascii_art += " ██  \n ██  \n ██  \n"
                    elif char == 'C':
                        ascii_art += " ▄▀█ \n █▄▄ \n ▀▀▀ \n"
                    elif char == 'D':
                        ascii_art += " ██  \n █ █ \n ██  \n"
                    elif char == 'E':
                        ascii_art += " ███ \n ██  \n ███ \n"
                    elif char == 'F':
                        ascii_art += " ███ \n ██  \n █   \n"
                    elif char == 'G':
                        ascii_art += " ▄▀█ \n █▄█ \n ▀▀▀ \n"
                    elif char == 'H':
                        ascii_art += " █ █ \n ███ \n █ █ \n"
                    elif char == 'I':
                        ascii_art += " ███ \n  █  \n ███ \n"
                    elif char == 'J':
                        ascii_art += " ███ \n   █ \n ██  \n"
                    elif char == ' ':
                        ascii_art += "     \n     \n     \n"
                    else:
                        ascii_art += " ▓▓▓ \n ▓▓▓ \n ▓▓▓ \n"

                st.text_area("ASCII Art:", ascii_art, height=150)

            elif art_style == "Banner":
                banner_text = ""
                for char in text_input.upper():
                    if char == 'A':
                        banner_text += "  ▄▀█  \n ▄▀▀▀▀▄ \n▀▄▄▄▄▀ \n"
                    elif char == 'B':
                        banner_text += " ▄▀▀▀▄  \n █▀▀▀▄  \n ▀▀▀▀▀  \n"
                    elif char == ' ':
                        banner_text += "        \n        \n        \n"
                    else:
                        banner_text += " ▓▓▓▓▓  \n ▓▓▓▓▓  \n ▓▓▓▓▓  \n"

                st.text_area("Banner ASCII Art:", banner_text, height=150)

            else:
                # Simple block or bubble style
                simple_art = f"╔{'═' * len(text_input)}╗\n║{text_input}║\n╚{'═' * len(text_input)}╝"
                st.text_area(f"{art_style} ASCII Art:", simple_art, height=100)

        elif tool == "Kaomoji Generator":
            kaomoji_categories = {
                "Happy": ["(◕‿◕)", "(＾◡＾)", "(✿◠‿◠)", "(◔‿◔)", "(◡‿◡)", "(＾▽＾)", "(´∀｀)", "(≧▽≦)",
                          "(＾ω＾)", "(◠＿◠)", "ヽ(´▽`)/", "(●´ω｀●)", "(＾◡＾)っ", "(´｡• ᵕ •｡`)", "( ◕ ‿ ◕ )"],
                "Sad": ["(╥﹏╥)", "(ಥ﹏ಥ)", "(｡•́︿•̀｡)", "(｡╯︵╰｡)", "(╯︵╰)", "(´･_･`)", "(╥_╥)",
                        "( ´･ω･`)", "(｡•̀ᴗ-)✧", "(◕︵◕)", "(╥﹏╥)", "｡ﾟ(ﾟ´(00)`ﾟ)ﾟ｡", "(੭ ˃̣̣̥ ㅂ˂̣̣̥)੭ु"],
                "Love": ["(♡‿♡)", "(◕‿◕)♡", "(✿ ♥‿♥)", "(´∀｀)♡", "♡(◡‿◡)♡", "(◍•ᴗ•◍)❤", "(｡♥‿♥｡)",
                         "♥‿♥", "(✧ω✧)", "♡(˃͈ દ ˂͈ ༶ )", "(◕દ◕)", "(*´∀｀*)", "♡〜٩(^▿^)۶〜♡"],
                "Angry": ["(╬ಠ益ಠ)", "(ಠ╭╮ಠ)", "(｀Д´)", "(╯°□°)╯", "(ノಠ益ಠ)ノ", "ヽ(ಠ_ಠ)ノ", "(ಠ_ಠ)",
                          "(ノ｀⌒´)ノ", "(╯︵╰,)", "( ಠ ʖ̯ ಠ)", "(▼へ▼メ)", "(◣_◢)", "(ﾟДﾟ；)"],
                "Surprised": ["(⊙_⊙)", "(◎_◎)", "(@_@)", "(゜-゜)", "(o_O)", "(O_O)", "(◉_◉)", "(⊙ω⊙)",
                              "(°o°)", "Σ(゜゜)", "( ºΔº )", "◉_◉", "ಠ_ಠ", "( ͡° ͜ʖ ͡°)", "(⊙﹏⊙)"],
                "Confused": ["(・_・)", "(￣_￣)", "(•_•)", "(-_-)", "(～_～)", "(¬_¬)", "(︶︿︶)", "(￣～￣)",
                             "(´･ω･`)?", "┐(￣ヘ￣)┌", "¯\\_(ツ)_/¯", "(・・?", "(◔_◔)", "(¬‿¬)", "┐( ˘_˘)┌"],
                "Excited": ["＼(^o^)／", "ヽ(°〇°)ﾉ", "ヾ(≧▽≦*)o", "＼(≧∇≦)／", "ヽ(´▽`)/", "┗(^0^)┓",
                            "ヾ(＾∇＾)", "ヽ(´∀｀)ノ", "ᕕ(ᐛ)ᕗ", "ヽ(' ∇' )ノ", "♪(´▽｀)", "ヽ(^。^)ノ"]
            }

            category = st.selectbox("Kaomoji category:", list(kaomoji_categories.keys()))
            selected_kaomojis = kaomoji_categories[category]

            # Display kaomojis in a grid
            cols = st.columns(5)
            for i, kaomoji in enumerate(selected_kaomojis):
                with cols[i % 5]:
                    st.text_input(f"Kaomoji {i + 1}:", kaomoji, key=f"kaomoji_{i}")

            st.info("Click on any kaomoji above to copy it!")


def miscellaneous_tools():
    """Miscellaneous Tools category"""
    st.title("🔧 Miscellaneous Tools")

    tool = st.selectbox("Select Tool:", [
        "QR Code Text Generator",
        "Barcode Generator (Text to Barcode)",
        "Text to Speech (TTS)",
        "Text Summarizer (AI based)",
        "AI Paraphraser",
        "AI Plagiarism Detector",
        "AI Blog Intro/Outro Generator"
    ])

    st.divider()
    text_input = st.text_area("Enter text:", height=100)

    if tool == "QR Code Text Generator":
        if text_input:
            qr = qrcode.QRCode(version=1, box_size=10, border=5)
            qr.add_data(text_input)
            qr.make(fit=True)
            img = qr.make_image(fill_color="black", back_color="white")
            # Convert PIL image to bytes for Streamlit
            img_buffer = BytesIO()
            img.save(img_buffer, format='PNG')
            st.image(img_buffer.getvalue(), caption="Generated QR Code")

    elif tool == "Text Summarizer (AI based)":
        if text_input:
            # Simple extractive summarization
            sentences = re.split(r'[.!?]+', text_input)
            sentences = [s.strip() for s in sentences if s.strip()]

            if len(sentences) > 3:
                # Take first, middle, and last sentences as summary
                summary_sentences = [sentences[0], sentences[len(sentences) // 2], sentences[-1]]
                summary = '. '.join(summary_sentences) + '.'
                st.text_area("Summary:", summary, height=100)
            else:
                st.info("Text too short to summarize effectively")

    elif tool == "AI Paraphraser":
        if text_input:
            # Simple word replacement paraphrasing
            replacements = {
                'very': 'extremely', 'good': 'excellent', 'bad': 'poor',
                'big': 'large', 'small': 'tiny', 'fast': 'quick',
                'slow': 'gradual', 'nice': 'pleasant', 'hard': 'difficult'
            }

            paraphrased = text_input
            for original, replacement in replacements.items():
                paraphrased = re.sub(r'\b' + original + r'\b', replacement, paraphrased, flags=re.IGNORECASE)

            st.text_area("Paraphrased text:", paraphrased, height=100)


def main():
    """Main application function"""
    if st.session_state.selected_category is None:
        main_page()
    else:
        # Add back button
        if st.button("← Back to Categories"):
            st.session_state.selected_category = None
            st.rerun()

        # Route to appropriate category function
        category_functions = {
            "Text Conversion Tools": text_conversion_tools,
            "Text Formatting & Cleaning Tools": text_formatting_tools,
            "Text Analysis Tools": text_analysis_tools,
            "Encoding & Encryption Tools": encoding_encryption_tools,
            "Text Generation Tools": text_generation_tools,
            "Language Tools": language_tools,
            "Text Extraction Tools": text_extraction_tools,
            "Text Editing Utilities": text_editing_utilities,
            "Text Styling Tools": text_styling_tools,
            "Miscellaneous": miscellaneous_tools
        }

        if st.session_state.selected_category in category_functions:
            category_functions[st.session_state.selected_category]()


if __name__ == "__main__":
    main()
