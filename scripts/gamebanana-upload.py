import os
import sys
import requests
import json
import time
import hmac
import hashlib
import base64
import struct
import urllib.parse
from dataclasses import dataclass
from selenium import webdriver
from selenium.common.exceptions import NoSuchElementException
from selenium.webdriver.common.by import By
from selenium.webdriver.support.wait import WebDriverWait
from selenium.webdriver.firefox.options import Options

def main():
    # Setup browser
    options = Options()
    # options.add_argument("--headless")
    
    driver = webdriver.Firefox(options=options)

    # Go to 404 page for less traffix
    driver.get("http://www.gamebanana.com/404")
    driver.implicitly_wait(5)
    time.sleep(5)

    # Retry until login is successful
    while True:
        # Authenticate
        print("Attempting login...", end="    ")
        twofac_code = compute_twofac_code(os.getenv("GAMEBANANA_2FA_URI"))
        driver.execute_script(fr"""
            fetch('https://gamebanana.com/apiv11/Member/Authenticate', {{
                'headers': {{
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36',
                    'Accept': 'application/json, text/plain, */*',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Content-Type': 'application/json',
                    'Sec-Fetch-Dest': 'empty',
                    'Sec-Fetch-Mode': 'cors',
                    'Sec-Fetch-Site': 'same-origin',
                    'Priority': 'u=0'
                }},
                'referrer': 'https://gamebanana.com/members/account/login',
                'body': '{{
                    "_sUsername":"{os.getenv("GAMEBANANA_USERNAME").replace(r'"', r'\"').replace('\\', '\\\\')}",
                    "_sPassword":"{os.getenv("GAMEBANANA_PASSWORD").replace(r'"', r'\"').replace('\\', '\\\\')}",
                    "_nTotp": "{twofac_code}"
                }}',
                'method': 'POST',
                'mode': 'cors',
                'credentials': 'include'
        }});
        """.replace('\n', ''))
        driver.implicitly_wait(5)
        time.sleep(5)

        driver.get(f"https://gamebanana.com/mods/edit/{os.getenv('GAMEBANANA_MODID')}")
        driver.implicitly_wait(5)
        time.sleep(5)

        try:
            driver.find_element(By.ID, "4dc48a0d0c19977f4533122b4194fc0f_FileInput")
            print("Success.")
            break
        except NoSuchElementException:
            print("Failure. Retrying...")

    # Check exiting file count
    beforeFileCount = driver.execute_script("return $('#4dc48a0d0c19977f4533122b4194fc0f_UploadedFiles li').length")
    driver.current_url

    if beforeFileCount >= 20:
        print("Deleting oldest file...", end="    ")
        # Need to delete oldest file to have enough space
        driver.execute_script("$('#4dc48a0d0c19977f4533122b4194fc0f_UploadedFiles li:last button').click()")

        wait = WebDriverWait(driver, timeout=2)
        alert = wait.until(lambda d : d.switch_to.alert)
        alert.accept()
        
        print("Done.")
        driver.implicitly_wait(1)
        time.sleep(1)

    # Upload file
    print("Uploading new file...", end="    ")
    driver.find_element(By.ID, "4dc48a0d0c19977f4533122b4194fc0f_FileInput").send_keys(os.path.join(os.getcwd(), sys.argv[1]))
    wait = WebDriverWait(driver, timeout=15, poll_frequency=.2)
    wait.until(lambda d : beforeFileCount != driver.execute_script("$('return #4dc48a0d0c19977f4533122b4194fc0f_UploadedFiles li').length"))
    print("Done.")
    driver.implicitly_wait(5)
    time.sleep(5)

    # Reorder to be the topmost
    print("Reordering new file to the top...", end="    ")
    driver.execute_script("$('#4dc48a0d0c19977f4533122b4194fc0f_UploadedFiles li:last').prependTo('#4dc48a0d0c19977f4533122b4194fc0f_UploadedFiles')")
    print("Done.")
    driver.implicitly_wait(1)
    time.sleep(1)

    # Submit
    print("Submitting edit...", end="    ")
    driver.execute_script("$('.Submit > button').click()")
    driver.implicitly_wait(10)
    print("Done.")

    driver.quit()

def compute_twofac_code(uri: str) -> str:
    secret, period, digits, algorithm = parse_otpauth_uri(uri)

    # Get the current time step (based on period)
    current_time = int(time.time())
    time_step = current_time // period

    # Generate the TOTP token
    return get_totp_token(secret, time_step, digits, algorithm)

def parse_otpauth_uri(uri):
    # Parse the URI
    parsed_uri = urllib.parse.urlparse(uri)
    query_params = urllib.parse.parse_qs(parsed_uri.query)
    
    # Extract the secret and other parameters
    secret = query_params.get('secret', [None])[0]
    period = int(query_params.get('period', [30])[0])
    digits = int(query_params.get('digits', [6])[0])
    algorithm = query_params.get('algorithm', ['SHA1'])[0].upper()
    
    return secret, period, digits, algorithm

def base32_decode(encoded_secret):
    # Add padding if necessary
    missing_padding = len(encoded_secret) % 8
    if missing_padding != 0:
        encoded_secret += '=' * (8 - missing_padding)
    # Decode the base32 secret
    return base64.b32decode(encoded_secret.upper())

def get_totp_token(secret, time_step, digits=6, algorithm='SHA1'):
    # HMAC key is the decoded secret
    key = base32_decode(secret)
    
    # Convert time_step to bytes (8-byte integer)
    time_step_bytes = struct.pack('>Q', time_step)
    
    # Choose the hash function (default to SHA1)
    if algorithm == 'SHA1':
        hash_function = hashlib.sha1
    elif algorithm == 'SHA256':
        hash_function = hashlib.sha256
    elif algorithm == 'SHA512':
        hash_function = hashlib.sha512
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")
    
    # Compute HMAC hash
    hmac_hash = hmac.new(key, time_step_bytes, hash_function).digest()
    
    # Extract dynamic binary code from HMAC hash
    offset = hmac_hash[-1] & 0x0F
    truncated_hash = hmac_hash[offset:offset + 4]
    truncated_hash = struct.unpack('>I', truncated_hash)[0] & 0x7FFFFFFF
    
    # Get the last 'digits' digits of the number
    totp_token = truncated_hash % (10 ** digits)
    
    return totp_token

if __name__ == "__main__":
    main()
