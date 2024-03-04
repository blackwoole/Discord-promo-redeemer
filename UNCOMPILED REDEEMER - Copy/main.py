from logger import *
from colorama import init, Fore, Style
import os
import uuid
from uuid import uuid4
import json
from json import load
import tls_client
import uuid
import ctypes
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Style,init
from datetime import datetime
from threading import Lock
from traceback import print_exc
from random import choice
lock = Lock()
import tls_client
import capsolver
import secrets
import requests
sT = tls_client.Session(
    ja3_string="771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0",

    h2_settings={

        "HEADER_TABLE_SIZE": 65536,

        "MAX_CONCURRENT_STREAMS": 1000,

        "INITIAL_WINDOW_SIZE": 6291456,

        "MAX_HEADER_LIST_SIZE": 262144

    },

    h2_settings_order=[

        "HEADER_TABLE_SIZE",

        "MAX_CONCURRENT_STREAMS",

        "INITIAL_WINDOW_SIZE",

        "MAX_HEADER_LIST_SIZE"

    ],

    supported_signature_algorithms=[

        "ECDSAWithP256AndSHA256",

        "PSSWithSHA256",

        "PKCS1WithSHA256",

        "ECDSAWithP384AndSHA384",

        "PSSWithSHA384",

        "PKCS1WithSHA384",

        "PSSWithSHA512",

        "PKCS1WithSHA512",

    ],

    supported_versions=["GREASE", "1.3", "1.2"],

    key_share_curves=["GREASE", "X25519"],

    cert_compression_algo="brotli",

    pseudo_header_order=[

        ":method",

        ":authority",

        ":scheme",

        ":path"

    ],

    connection_flow=15663105,

    header_order=[

        "accept",

        "user-agent",

        "accept-encoding",

        "accept-language"

    ]
)    
import ctypes
import threading
from licensing.models import *
from licensing.methods import Key, Helpers
import time
import sys
init()
message_id = None
claimed = 0
failed = 0
processed = 0

def set_console_title():
    ctypes.windll.kernel32.SetConsoleTitleW(f'Express 1.0 | Claimed: {claimed} | Failed: {failed} | Processed: {processed}')
set_console_title()
message_ids = []

def send_discord_webhook(url):
    global message_ids
    payload = {
        "content": f'```[Promo-Redeemer] : Claimed: {claimed} | Failed: {failed} | Processed: {processed}```'
    }
    headers = {
        "Content-Type": "application/json"
    }

    if message_ids:
        latest_message_id = message_ids[-1]
        response = requests.patch(f"{url}/messages/{latest_message_id}", data=json.dumps(payload), headers=headers)
        if response.status_code == 200:
            return
        else:
            return
    else:
        response = requests.post(url, data=json.dumps(payload), headers=headers)
        if response.status_code == 200:
            message_id = response.json().get("id")
            message_ids.append(message_id)
            return
        else:
            return
with open('config.json', 'r') as f:
   config = json.load(f)
try:
  promoType = config["promoType"]
  cardName = config["cardName"]
  line_1 = config["line_1"]
  city = config["city"]
  state = config["state"]
  postalcode = config["postalcode"]
  country = config["country"]
  ipg = config["inbuilt-promo-gen"]["use-inbuilt-promo-gen"]
  kipg = config["inbuilt-promo-gen"]["capsolverkey"]
  wurl = config["webhookurl"]
  sj = config["proxySupport"]
  isOn = config["custom-branding"]["custom-branding"]
  dName = config["custom-branding"]["displayName"]
  cIsOn = config["capsolver-support"]["usecapsolver"]
  cKey = config["capsolver-support"]["key"]
except:
   Eprint("ERROR OCCURED FETCHING DATAS FROM config.json!")
# https://github.com/notlit69/OperaGX-Promo-Gen/blob/main/main.py
class Utils:
    def get_soln() -> str|None:
        try:
            capsolver.api_key = kipg
            soln = capsolver.solve({
            "type": "ReCaptchaV2TaskProxyLess",
            "websiteURL": "https://auth.opera.com/account/authenticate/email",
            "websiteKey": "6LdYcFgaAAAAAEH3UnuL-_eZOsZc-32lGOyrqfA4",
          })['gRecaptchaResponse']
            return soln
        except Exception as e:
            Logger.Sprint("ERROR",f"Captcha Error: {str(e)}",Fore.RED)
            return None

class Logger:
    @staticmethod
    def Sprint(tag: str, content: str, color) -> None:
        ts = f"{Fore.RESET}{Fore.LIGHTBLACK_EX}{datetime.now().strftime('%H:%M:%S')}{Fore.RESET}"
        with lock:
            print(f"{Style.BRIGHT}{ts}{color} [{tag}] {Fore.RESET}{content}{Fore.RESET}")
    @staticmethod
    def Ask(tag: str, content: str, color):
        ts = f"{Fore.RESET}{Fore.LIGHTBLACK_EX}{datetime.now().strftime('%H:%M:%S')}{Fore.RESET}"
        return input(f"{Style.BRIGHT}{ts}{color} [{tag}] {Fore.RESET}{content}{Fore.RESET}")

class Opera:
    def __init__(self) -> None:
        self.session = requests.Session()
        self.session.proxies = None
        self.user = secrets.token_hex(10)
        self.email = f"{self.user}@"+choice(['gmail.com','outlook.com','yahoo.com','hotmail.com'])
        self.user_agent = secrets.token_hex(10) # fire user agent 
        self.session.headers={
    'user-agent': self.user_agent,
}
    def exec_request(self,*args,**kwargs) -> requests.Response:
        for x in range(50):
            try:
                return self.session.request(*args,**kwargs)
            except:
                # print_exc()
                continue
        else:
            raise Exception("Failed To Execute Request After 50x Retries!")
    def post_request(self, *args, **kwargs) -> requests.Response:
        return self.exec_request("POST",*args,**kwargs)
    def get_request(self, *args, **kwargs) -> requests.Response:
        return self.exec_request("GET",*args,**kwargs)

    def regAndAuth(self) -> bool:
        self.get_request("https://auth.opera.com/account/authenticate",allow_redirects=True)
        start = time.time()
        soln = Utils.get_soln() 
        if not soln:
            return False
        self.session.headers['x-language-locale'] = 'en'
        self.session.headers['referer'] = 'https://auth.opera.com/account/authenticate/signup'
        signUp = self.post_request("https://auth.opera.com/account/v4/api/signup",json={
    'email': self.email,
    'password': self.user,
    'password_repeated': self.user,
    'marketing_consent': False,
    'captcha' : soln,
    'services': ['gmx']})
        if "429" in signUp.text:
            return False
        if not signUp.status_code in [200,201,204]:
            return False
        self.session.headers['x-csrftoken'] = self.session.cookies.get_dict()['__Host-csrftoken']
        profile = self.exec_request("PATCH","https://auth.opera.com/api/v1/profile",json={"username":self.user})
        if not profile.status_code in [200,201,204]:
            return False
        self.session.headers = {
    'authority': 'api.gx.me',
    'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'accept-language': 'en-US,en;q=0.9',
    'referer': 'https://gx.me/signup/?utm_source=gxdiscord',
    'sec-ch-ua': '"Not A(Brand";v="99", "Opera GX";v="107", "Chromium";v="121"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'document',
    'sec-fetch-mode': 'navigate',
    'sec-fetch-site': 'same-site',
    'upgrade-insecure-requests': '1',
    'user-agent': self.user_agent,
}
        self.get_request("https://api.gx.me/session/login?site=gxme&target=%2F",allow_redirects=True)
        self.get_request("https://auth.opera.com/account/login-redirect?service=gmx",allow_redirects=True)
        return True
        
    def gen(self) -> None:
        global genned
        for x in range(3):
            if not self.regAndAuth():
                continue
            break
        else:
            return 
        auth = self.get_request("https://api.gx.me/profile/token").json()['data']
        promoReq = self.post_request('https://discord.opr.gg/v2/direct-fulfillment', headers={
    'authorization': auth,
    'origin': 'https://www.opera.com',
    'referer': 'https://www.opera.com/',
    'user-agent': self.user_agent,
})
        if not "token" in promoReq.text or not promoReq.ok:
            return 
        promo = "https://discord.com/billing/partner-promotions/1180231712274387115/{}".format(promoReq.json()['token'])
        return promo
class REDEEMER:
    def __init__(self, token: str, full_vcc: str, promoCode: str, proxy: str):
        global processed, failed, claimed
        if ':' in full_vcc:
          self.ccn = full_vcc.split(':')[0]
          self.expMa = full_vcc.split(':')[1]
          self.expM = self.expMa[:2]
          self.expY = self.expMa[2:]
          self.cvv = full_vcc.split(':')[2]
        elif '|' in full_vcc:
           self.ccn, self.expM, self.expY, self.cvv = full_vcc.split('|')
        else:
           print("[-] invalid vcc-format.")
           return ''
        if '@' in token:
           self.token = token.split(':')[2]
        else:
          self.token = token
        self.promoz = promoCode
        processed += 1
        if proxy:
          self.proxy = f"http://{proxy}"
        else:
           self.proxy = None
        set_console_title()

    def getSubscriptionId(self):
      headers = {
    'authority': 'discord.com',
    'accept': '*/*',
    'accept-language': 'en-US,en;q=0.9',
    'authorization': self.token,
    # 'cookie': '__dcfduid=2458d570da0411eebe6e354350a588c5; __sdcfduid=2458d571da0411eebe6e354350a588c58c7f5333f935f0f6e60c1a8386bdce9405c5aa8e37c55b9a6385f47732eaa85e; cf_clearance=a17CnElp_nM_3yPQeCVxaPPjQqYYA3ydWXzNzEwTykg-1709542184-1.0.1.1-Kgl9FfTqIhM.6bndxRc4KPLJJrAWgOjWR0D6hV1OY8I30UWwxB9kvV0u1EOFmWk4nOiWdrUuwdBi4hixq9rYPA; __cfruid=146c0694d5ebabc9674c27044a63c08a487c6c12-1709546676; _cfuvid=g1Dl3Gb2egXVZcEPihhQ8pu20G2w2c2kFtx.TPo72oc-1709546676264-0.0.1.1-604800000',
    'referer': 'https://discord.com/channels/@me',
    'sec-ch-ua': '"Chromium";v="122", "Not(A:Brand";v="24", "Microsoft Edge";v="122"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'empty',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'same-origin',
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0',
    'x-debug-options': 'bugReporterEnabled',
    'x-discord-locale': 'en-US',
    'x-discord-timezone': 'Europe/Budapest',
    'x-super-properties': 'eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiQ2hyb21lIiwiZGV2aWNlIjoiIiwic3lzdGVtX2xvY2FsZSI6ImVuLVVTIiwiYnJvd3Nlcl91c2VyX2FnZW50IjoiTW96aWxsYS81LjAgKFdpbmRvd3MgTlQgMTAuMDsgV2luNjQ7IHg2NCkgQXBwbGVXZWJLaXQvNTM3LjM2IChLSFRNTCwgbGlrZSBHZWNrbykgQ2hyb21lLzEyMi4wLjAuMCBTYWZhcmkvNTM3LjM2IEVkZy8xMjIuMC4wLjAiLCJicm93c2VyX3ZlcnNpb24iOiIxMjIuMC4wLjAiLCJvc192ZXJzaW9uIjoiMTAiLCJyZWZlcnJlciI6IiIsInJlZmVycmluZ19kb21haW4iOiIiLCJyZWZlcnJlcl9jdXJyZW50IjoiIiwicmVmZXJyaW5nX2RvbWFpbl9jdXJyZW50IjoiIiwicmVsZWFzZV9jaGFubmVsIjoic3RhYmxlIiwiY2xpZW50X2J1aWxkX251bWJlciI6MjcxMjE2LCJjbGllbnRfZXZlbnRfc291cmNlIjpudWxsfQ==',
}
      response = sT.get('https://discord.com/api/v9/users/@me/billing/subscriptions', headers=headers)
      json_data = response.json()
      return json_data[0]["id"]
     
    def GetPromoCode(self):
       headerz = {
    'authority': 'discord.com',
    'accept': '*/*',
    'accept-language': 'en-US,en;q=0.9',
    'authorization': self.token,
    'content-type': 'application/json',
    'origin': 'https://discord.com',
    'referer': self.promoz,
    'sec-ch-ua': '"Chromium";v="122", "Not(A:Brand";v="24", "Microsoft Edge";v="122"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'empty',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'same-origin',
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0',
    'x-debug-options': 'bugReporterEnabled',
    'x-discord-locale': 'en-US',
    'x-discord-timezone': 'Europe/Budapest',
    'x-super-properties': 'eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiQ2hyb21lIiwiZGV2aWNlIjoiIiwic3lzdGVtX2xvY2FsZSI6ImVuLVVTIiwiYnJvd3Nlcl91c2VyX2FnZW50IjoiTW96aWxsYS81LjAgKFdpbmRvd3MgTlQgMTAuMDsgV2luNjQ7IHg2NCkgQXBwbGVXZWJLaXQvNTM3LjM2IChLSFRNTCwgbGlrZSBHZWNrbykgQ2hyb21lLzEyMi4wLjAuMCBTYWZhcmkvNTM3LjM2IEVkZy8xMjIuMC4wLjAiLCJicm93c2VyX3ZlcnNpb24iOiIxMjIuMC4wLjAiLCJvc192ZXJzaW9uIjoiMTAiLCJyZWZlcnJlciI6Imh0dHBzOi8vZGlzY29yZC5jb20vP2Rpc2NvcmR0b2tlbj1NVEEzTURReU56RXhNVGM1TVRJNE5ESTROQS5HYWNhYnIuVE9NZUVzbHdiczJ2OFRlck4wOTM3SzVvS0ZFMFZyZW5fdWF6Q1kiLCJyZWZlcnJpbmdfZG9tYWluIjoiZGlzY29yZC5jb20iLCJyZWZlcnJlcl9jdXJyZW50IjoiIiwicmVmZXJyaW5nX2RvbWFpbl9jdXJyZW50IjoiIiwicmVsZWFzZV9jaGFubmVsIjoic3RhYmxlIiwiY2xpZW50X2J1aWxkX251bWJlciI6MjY4NjAwLCJjbGllbnRfZXZlbnRfc291cmNlIjpudWxsfQ==',
}
       if promoType == '1m':
        jwt = self.promoz.split('https://discord.com/billing/partner-promotions/1180231712274387115/')[1]
       else:
          jwt = self.promoz.split('https://discord.com/billing/promotions/')[1]
       json_datas = {
    'jwt': jwt,
}
       responsez = sT.post(
    'https://discord.com/api/v9/entitlements/partner-promotions/1180231712274387115',
    headers=headerz,
    json=json_datas
)
       try:
          if responsez.status_code == 200:
            codez = responsez.json()["code"]
            return codez
          else:
             Eprint(f'{Fore.LIGHTRED_EX}[ERROR] {Fore.LIGHTMAGENTA_EX}- {Fore.LIGHTCYAN_EX}Error Fetching Promo-Code')
             with open('database/promoFailedFetchCode.txt', 'a') as fas:
                fas.write(f"{self.promoz}\n")
       except Exception as e:
          Eprint(f'{Fore.LIGHTRED_EX}[ERROR] {Fore.LIGHTMAGENTA_EX}- {Fore.LIGHTCYAN_EX}Unhandled Error Fetching promo-code')
          with open('database/promoFailedFetchCode.txt', 'a') as fas:
                fas.write(f"{self.promoz}\n")
          return 'F'
    def get_soln(self) -> str|None:
        try:
            capsolver.api_key = cKey
            soln = capsolver.solve({
            "type": "HCaptchaTaskProxyLess",
            "websiteURL": "https://discord.com/",
            "websiteKey": "472b4c9f-f2b7-4382-8135-c983f5496eb9",
          })['gRecaptchaResponse']
            return soln
        except Exception as e:
            Eprint(f"{Fore.LIGHTRED_EX}[ERROR] {Fore.LIGHTMAGENTA_EX}- {Fore.LIGHTCYAN_EX}Error Solving Captcha [{Fore.LIGHTMAGENTA_EX}CAPSOLVER{Fore.LIGHTCYAN_EX}], EXC -> {Fore.LIGHTMAGENTA_EX}{e}")
            return None
    def cancle_subscription(self,subsid):
        headers = {
    'authority': 'discord.com',
    'accept': '*/*',
    'accept-language': 'en-US,en;q=0.9',
    'authorization': self.token,
    'content-type': 'application/json',
    # 'cookie': '__dcfduid=3aa2e550d88811ee8ebe6f2ec480765f; __sdcfduid=3aa2e551d88811ee8ebe6f2ec480765f52ad3c70d6fba937f26437b3b34748f837ede062b02e78b1857ee3dd206fe25c; __cfruid=8705d1991b6d5ce8ce8fc1123e62dfdd307415df-1709379010; _cfuvid=mkce45BcHN47tPvNUq2inSfswqa99yPxlYHXxJdsLrs-1709379010600-0.0.1.1-604800000; cf_clearance=Zzc_p_LPCf3jUlQP4xgL4haLaDvcTFdAWBlrFtJSnF0-1709379013-1.0.1.1-Ore_ztu.aA6E0JQ7T7BV1jq4fcz.zj2Z.f99Pt0Jz.OiLAAEnhp9gCIQF1GeGB9X3NwxloqetlsWGiU_6TwlQg',
    'origin': 'https://discord.com',
    'referer': 'https://discord.com/channels/@me',
    'sec-ch-ua': '"Chromium";v="122", "Not(A:Brand";v="24", "Microsoft Edge";v="122"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'empty',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'same-origin',
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0',
    'x-debug-options': 'bugReporterEnabled',
    'x-discord-locale': 'en-US',
    'x-discord-timezone': 'Europe/Budapest',
    'x-super-properties': 'eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiQ2hyb21lIiwiZGV2aWNlIjoiIiwic3lzdGVtX2xvY2FsZSI6ImVuLVVTIiwiYnJvd3Nlcl91c2VyX2FnZW50IjoiTW96aWxsYS81LjAgKFdpbmRvd3MgTlQgMTAuMDsgV2luNjQ7IHg2NCkgQXBwbGVXZWJLaXQvNTM3LjM2IChLSFRNTCwgbGlrZSBHZWNrbykgQ2hyb21lLzEyMi4wLjAuMCBTYWZhcmkvNTM3LjM2IEVkZy8xMjIuMC4wLjAiLCJicm93c2VyX3ZlcnNpb24iOiIxMjIuMC4wLjAiLCJvc192ZXJzaW9uIjoiMTAiLCJyZWZlcnJlciI6IiIsInJlZmVycmluZ19kb21haW4iOiIiLCJyZWZlcnJlcl9jdXJyZW50IjoiIiwicmVmZXJyaW5nX2RvbWFpbl9jdXJyZW50IjoiIiwicmVsZWFzZV9jaGFubmVsIjoic3RhYmxlIiwiY2xpZW50X2J1aWxkX251bWJlciI6MjcxMjE2LCJjbGllbnRfZXZlbnRfc291cmNlIjpudWxsfQ==',
}
        payload = {
            "payment_source_token": None,
            "gateway_checkout_context": None,
            "items": []
        }
        params = {
    'location_stack': [
        'user settings',
        'subscription header',
        'premium subscription cancellation modal',
    ],
}
        response = sT.patch(
    f'https://discord.com/api/v9/users/@me/billing/subscriptions/{subsid}',
    params=params,
    headers=headers,
    json=payload,
)
        if response.status_code in (200, 201, 202, 203, 204):
            return True

        Eprint('Failed to remove payment method!')
        return False

    def removeCard(self, idz: str):
       global processed, failed, claimed
       headersz = {
    'authority': 'discord.com',
    'accept': '*/*',
    'accept-language': 'en-US,en;q=0.9',
    'authorization': self.token,
    'origin': 'https://discord.com',
    'referer': 'https://discord.com/channels/@me/1209553062172172372',
    'sec-ch-ua': '"Chromium";v="122", "Not(A:Brand";v="24", "Microsoft Edge";v="122"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'empty',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'same-origin',
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0',
    'x-debug-options': 'bugReporterEnabled',
    'x-discord-locale': 'en-US',
    'x-discord-timezone': 'Europe/Budapest',
    'x-super-properties': 'eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiQ2hyb21lIiwiZGV2aWNlIjoiIiwic3lzdGVtX2xvY2FsZSI6ImVuLVVTIiwiYnJvd3Nlcl91c2VyX2FnZW50IjoiTW96aWxsYS81LjAgKFdpbmRvd3MgTlQgMTAuMDsgV2luNjQ7IHg2NCkgQXBwbGVXZWJLaXQvNTM3LjM2IChLSFRNTCwgbGlrZSBHZWNrbykgQ2hyb21lLzEyMi4wLjAuMCBTYWZhcmkvNTM3LjM2IEVkZy8xMjIuMC4wLjAiLCJicm93c2VyX3ZlcnNpb24iOiIxMjIuMC4wLjAiLCJvc192ZXJzaW9uIjoiMTAiLCJyZWZlcnJlciI6Imh0dHBzOi8vZGlzY29yZC5jb20vP2Rpc2NvcmR0b2tlbj1NVEEzTURReU56RXhNVGM1TVRJNE5ESTROQS5HYWNhYnIuVE9NZUVzbHdiczJ2OFRlck4wOTM3SzVvS0ZFMFZyZW5fdWF6Q1kiLCJyZWZlcnJpbmdfZG9tYWluIjoiZGlzY29yZC5jb20iLCJyZWZlcnJlcl9jdXJyZW50IjoiIiwicmVmZXJyaW5nX2RvbWFpbl9jdXJyZW50IjoiIiwicmVsZWFzZV9jaGFubmVsIjoic3RhYmxlIiwiY2xpZW50X2J1aWxkX251bWJlciI6MjY5MTY2LCJjbGllbnRfZXZlbnRfc291cmNlIjpudWxsfQ==',
}
       responsez = sT.delete(
    f'https://discord.com/api/v9/users/@me/billing/payment-sources/{idz}',
    headers=headersz
)
       if responsez.status_code == 204:
          Uprint()
          return 'S'
       else:
          Wprint(f'Failed To Remove Vcc.')
          with open('database/FailedRemoveVccCCS.txt') as fx:
             fx.write(f"{self.ccn}:{self.expM}:{self.expY}:{self.cvv}\n")
          with open('database/FailedRemoveVccTokens.txt') as fx:
             fx.write(f"{self.token}\n")
          return responsez.json() 
    def RedeemPromo(self, id: str):
       global processed, failed, claimed
       if id == 'F':
          return 'Fa'
       else:
        if promoType == '1m':
         codes = self.GetPromoCode()
         headers = {
    'authority': 'discord.com',
    'accept': '*/*',
    'accept-language': 'en-US,en;q=0.9',
    'authorization': self.token,
    'content-type': 'application/json',
    'origin': 'https://discord.com',
    'referer': f'https://discord.com/billing/promotions/{codes}',
    'sec-ch-ua': '"Chromium";v="122", "Not(A:Brand";v="24", "Microsoft Edge";v="122"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'empty',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'same-origin',
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0',
    'x-debug-options': 'bugReporterEnabled',
    'x-discord-locale': 'en-US',
    'x-discord-timezone': 'Europe/Budapest',
    'x-super-properties': 'eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiQ2hyb21lIiwiZGV2aWNlIjoiIiwic3lzdGVtX2xvY2FsZSI6ImVuLVVTIiwiYnJvd3Nlcl91c2VyX2FnZW50IjoiTW96aWxsYS81LjAgKFdpbmRvd3MgTlQgMTAuMDsgV2luNjQ7IHg2NCkgQXBwbGVXZWJLaXQvNTM3LjM2IChLSFRNTCwgbGlrZSBHZWNrbykgQ2hyb21lLzEyMi4wLjAuMCBTYWZhcmkvNTM3LjM2IEVkZy8xMjIuMC4wLjAiLCJicm93c2VyX3ZlcnNpb24iOiIxMjIuMC4wLjAiLCJvc192ZXJzaW9uIjoiMTAiLCJyZWZlcnJlciI6IiIsInJlZmVycmluZ19kb21haW4iOiIiLCJyZWZlcnJlcl9jdXJyZW50IjoiIiwicmVmZXJyaW5nX2RvbWFpbl9jdXJyZW50IjoiIiwicmVsZWFzZV9jaGFubmVsIjoic3RhYmxlIiwiY2xpZW50X2J1aWxkX251bWJlciI6MjY4NjAwLCJjbGllbnRfZXZlbnRfc291cmNlIjpudWxsfQ==',
}
        else:
           codes = str(self.promoz).split('https://discord.com/billing/promotions/')[1]
           headers = {
    'authority': 'discord.com',
    'accept': '*/*',
    'accept-language': 'en-US,en;q=0.9',
    'authorization': self.token,
    'content-type': 'application/json',
    'origin': 'https://discord.com',
    'referer': f'https://discord.com/billing/promotions/{codes}',
    'sec-ch-ua': '"Chromium";v="122", "Not(A:Brand";v="24", "Microsoft Edge";v="122"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'empty',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'same-origin',
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0',
    'x-debug-options': 'bugReporterEnabled',
    'x-discord-locale': 'en-US',
    'x-discord-timezone': 'Europe/Budapest',
    'x-super-properties': 'eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiQ2hyb21lIiwiZGV2aWNlIjoiIiwic3lzdGVtX2xvY2FsZSI6ImVuLVVTIiwiYnJvd3Nlcl91c2VyX2FnZW50IjoiTW96aWxsYS81LjAgKFdpbmRvd3MgTlQgMTAuMDsgV2luNjQ7IHg2NCkgQXBwbGVXZWJLaXQvNTM3LjM2IChLSFRNTCwgbGlrZSBHZWNrbykgQ2hyb21lLzEyMi4wLjAuMCBTYWZhcmkvNTM3LjM2IEVkZy8xMjIuMC4wLjAiLCJicm93c2VyX3ZlcnNpb24iOiIxMjIuMC4wLjAiLCJvc192ZXJzaW9uIjoiMTAiLCJyZWZlcnJlciI6Imh0dHBzOi8vZGlzY29yZC5jb20vP2Rpc2NvcmR0b2tlbj1NVEEzTURReU56RXhNVGM1TVRJNE5ESTROQS5HYWNhYnIuVE9NZUVzbHdiczJ2OFRlck4wOTM3SzVvS0ZFMFZyZW5fdWF6Q1kiLCJyZWZlcnJpbmdfZG9tYWluIjoiZGlzY29yZC5jb20iLCJyZWZlcnJlcl9jdXJyZW50IjoiIiwicmVmZXJyaW5nX2RvbWFpbl9jdXJyZW50IjoiIiwicmVsZWFzZV9jaGFubmVsIjoic3RhYmxlIiwiY2xpZW50X2J1aWxkX251bWJlciI6MjY4NjAwLCJjbGllbnRfZXZlbnRfc291cmNlIjpudWxsfQ==',
}
        jsonP = {
    'channel_id': None,
    'payment_source_id': id,
    'gateway_checkout_context': None,
}
        r = sT.post(
    f'https://discord.com/api/v9/entitlements/gift-codes/{codes}/redeem',
    headers=headers,
    json=jsonP
)
        try:
          ase = r.json()["id"]
          Sprint(f"{self.token[:23]}***")
          claimed += 1
          set_console_title()
          send_discord_webhook(wurl)
          with open('outputSuccess/successPromo.txt', 'a') as sp:
             sp.write(f"{self.promoz}\n")
          with open('outputSuccess/successTokens.txt', 'a') as st:
             st.write(f"{self.token}\n")
          with open('outputSuccess/successVcc.txt', 'a') as sv:
             sv.write(f"{self.ccn}:{self.expM}:{self.expY}:{self.cvv}\n")
          subid = self.getSubscriptionId()
          ale = self.cancle_subscription(subid)
          rr = self.removeCard(id)
          if rr == 'S':
             return ''
          else:
             print(rr)
        except Exception as e:
          Eprint(f'{Fore.LIGHTRED_EX}[ERROR] {Fore.LIGHTMAGENTA_EX}- {Fore.LIGHTCYAN_EX}Failed Claiming Promo.')
          failed += 1
          send_discord_webhook(wurl)
          set_console_title()
          with open('outputFails/failedPromos.txt', 'a') as sp:
             sp.write(f"{self.promoz}\n")
          with open('outputFails/failedTokens.txt', 'a') as st:
             st.write(f"{self.token}\n")
          with open('outputFails/failedVccs.txt', 'a') as sv:
             sv.write(f"{self.ccn}:{self.expM}:{self.expY}:{self.cvv}\n")
          with open('database/cardFailed.txt', 'a') as sv:
             sv.write(f"{self.ccn}:{self.expM}:{self.expY}:{self.cvv}\n")
          if 'Authentication' in r.text:
             return 'Ar'
          else:
             return None
    def AddCard(self):
       global processed, failed, claimed
       Aprint(f"{self.ccn}")
       header1 = {
    'authority': 'api.stripe.com',
    'accept': 'application/json',
    'accept-language': 'en-US,en;q=0.9',
    'content-type': 'application/x-www-form-urlencoded',
    'origin': 'https://js.stripe.com',
    'referer': 'https://js.stripe.com/',
    'sec-ch-ua': '"Chromium";v="122", "Not(A:Brand";v="24", "Microsoft Edge";v="122"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'empty',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'same-site',
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0',
}
       data = f'card[number]={self.ccn}&card[cvc]={self.cvv}&card[exp_month]={self.expM}&card[exp_year]={self.expY}&guid={uuid.uuid4()}&muid={uuid.uuid4()}&sid={uuid.uuid4}&payment_user_agent=stripe.js%2F28b7ba8f85%3B+stripe-js-v3%2F28b7ba8f85%3B+split-card-element&referrer=https%3A%2F%2Fdiscord.com&time_on_page=415638&key=pk_live_CUQtlpQUF0vufWpnpUmQvcdi&pasted_fields=number%2Ccvc'
       response = sT.post('https://api.stripe.com/v1/tokens', proxy=self.proxy, headers=header1, data=data)
       try:
          TokenCard = response.json()["id"]
       except Exception as e:
          Eprint(f'{Fore.LIGHTRED_EX}[ERROR] {Fore.LIGHTMAGENTA_EX}- {Fore.LIGHTCYAN_EX}Failed Adding Card 444')
          failed += 1
          send_discord_webhook(wurl)
          set_console_title()
          with open('outputFails/failedPromos.txt', 'a') as sp:
             sp.write(f"{self.promoz}\n")
          with open('outputFails/failedTokens.txt', 'a') as st:
             st.write(f"{self.token}\n")
          with open('outputFails/failedVccs.txt', 'a') as sv:
             sv.write(f"{self.ccn}:{self.expM}:{self.expY}:{self.cvv}\n")
          with open('database/cardFailed.txt', 'a') as ae:
             ae.write(f"{self.ccn}:{self.expM}:{self.expY}:{self.cvv}\n")
          with open('database/failedDatabaseWithErrors.txt', 'a') as fs:
             fs.write(f"{self.token}:{self.ccn}:{self.expM}:{self.expY}:{self.cvv} -> JSON RESPONSE: {response.json()}\n")
          return 'F'
       header2 = {
    'authority': 'discord.com',
    'accept': '*/*',
    'accept-language': 'en-US,en;q=0.9',
    'authorization': self.token,
    'origin': 'https://discord.com',
    'referer': 'https://discord.com/channels/@me',
    'sec-ch-ua': '"Chromium";v="122", "Not(A:Brand";v="24", "Microsoft Edge";v="122"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'empty',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'same-origin',
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0',
    'x-debug-options': 'bugReporterEnabled',
    'x-discord-locale': 'en-US',
    'x-discord-timezone': 'Europe/Budapest',
    'x-super-properties': 'eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiQ2hyb21lIiwiZGV2aWNlIjoiIiwic3lzdGVtX2xvY2FsZSI6ImVuLVVTIiwiYnJvd3Nlcl91c2VyX2FnZW50IjoiTW96aWxsYS81LjAgKFdpbmRvd3MgTlQgMTAuMDsgV2luNjQ7IHg2NCkgQXBwbGVXZWJLaXQvNTM3LjM2IChLSFRNTCwgbGlrZSBHZWNrbykgQ2hyb21lLzEyMi4wLjAuMCBTYWZhcmkvNTM3LjM2IEVkZy8xMjIuMC4wLjAiLCJicm93c2VyX3ZlcnNpb24iOiIxMjIuMC4wLjAiLCJvc192ZXJzaW9uIjoiMTAiLCJyZWZlcnJlciI6IiIsInJlZmVycmluZ19kb21haW4iOiIiLCJyZWZlcnJlcl9jdXJyZW50IjoiIiwicmVmZXJyaW5nX2RvbWFpbl9jdXJyZW50IjoiIiwicmVsZWFzZV9jaGFubmVsIjoic3RhYmxlIiwiY2xpZW50X2J1aWxkX251bWJlciI6MjY4NjAwLCJjbGllbnRfZXZlbnRfc291cmNlIjpudWxsfQ==',
}
       response = sT.post('https://discord.com/api/v9/users/@me/billing/stripe/setup-intents', headers=header2, proxy=self.proxy)
       try:
          csTok = response.json()["client_secret"]
          Stok = str(csTok).split('_secret_')[0]
       except Exception as e:
          Eprint(f'{Fore.LIGHTRED_EX}[ERROR] {Fore.LIGHTMAGENTA_EX}- {Fore.LIGHTCYAN_EX}Failed Adding Card 485')
          failed += 1
          send_discord_webhook(wurl)
          set_console_title()
          with open('outputFails/failedPromos.txt', 'a') as sp:
             sp.write(f"{self.promoz}\n")
          with open('outputFails/failedTokens.txt', 'a') as st:
             st.write(f"{self.token}\n")
          with open('outputFails/failedVccs.txt', 'a') as sv:
             sv.write(f"{self.ccn}:{self.expM}:{self.expY}:{self.cvv}\n")
          with open('database/cardFailed.txt', 'a') as ae:
             ae.write(f"{self.ccn}:{self.expM}:{self.expY}:{self.cvv}\n")
          with open('database/failedDatabaseWithErrors.txt', 'a') as fs:
             fs.write(f"{self.token}:{self.ccn}:{self.expM}:{self.expY}:{self.cvv} -> JSON RESPONSE: {response.json()}\n")
          return 'F'
       header3 = {
    'authority': 'discord.com',
    'accept': '*/*',
    'accept-language': 'en-US,en;q=0.9',
    'authorization': self.token,
    'content-type': 'application/json',
    'origin': 'https://discord.com',
    'referer': 'https://discord.com/channels/@me',
    'sec-ch-ua': '"Chromium";v="122", "Not(A:Brand";v="24", "Microsoft Edge";v="122"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'empty',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'same-origin',
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0',
    'x-debug-options': 'bugReporterEnabled',
    'x-discord-locale': 'en-US',
    'x-discord-timezone': 'Europe/Budapest',
    'x-super-properties': 'eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiQ2hyb21lIiwiZGV2aWNlIjoiIiwic3lzdGVtX2xvY2FsZSI6ImVuLVVTIiwiYnJvd3Nlcl91c2VyX2FnZW50IjoiTW96aWxsYS81LjAgKFdpbmRvd3MgTlQgMTAuMDsgV2luNjQ7IHg2NCkgQXBwbGVXZWJLaXQvNTM3LjM2IChLSFRNTCwgbGlrZSBHZWNrbykgQ2hyb21lLzEyMi4wLjAuMCBTYWZhcmkvNTM3LjM2IEVkZy8xMjIuMC4wLjAiLCJicm93c2VyX3ZlcnNpb24iOiIxMjIuMC4wLjAiLCJvc192ZXJzaW9uIjoiMTAiLCJyZWZlcnJlciI6IiIsInJlZmVycmluZ19kb21haW4iOiIiLCJyZWZlcnJlcl9jdXJyZW50IjoiIiwicmVmZXJyaW5nX2RvbWFpbl9jdXJyZW50IjoiIiwicmVsZWFzZV9jaGFubmVsIjoic3RhYmxlIiwiY2xpZW50X2J1aWxkX251bWJlciI6MjY4NjAwLCJjbGllbnRfZXZlbnRfc291cmNlIjpudWxsfQ==',
}
       jsonD = {
    'billing_address': {
        'name': cardName,
        'line_1': line_1,
        'line_2': '',
        'city': city,
        'state': state,
        'postal_code': postalcode,
        'country': country,
        'email': '',
    },
}
       response = sT.post(
    'https://discord.com/api/v9/users/@me/billing/payment-sources/validate-billing-address',
    headers=header3,
    json=jsonD, proxy=self.proxy
)
       try:
          BTok = response.json()["token"]
       except Exception as e:
          Eprint(f'{Fore.LIGHTRED_EX}[ERROR] {Fore.LIGHTMAGENTA_EX}- {Fore.LIGHTCYAN_EX}Failed Adding Card 536')
          failed += 1
          send_discord_webhook(wurl)
          set_console_title()
          with open('outputFails/failedPromos.txt', 'a') as sp:
             sp.write(f"{self.promoz}\n")
          with open('outputFails/failedTokens.txt', 'a') as st:
             st.write(f"{self.token}\n")
          with open('outputFails/failedVccs.txt', 'a') as sv:
             sv.write(f"{self.ccn}:{self.expM}:{self.expY}:{self.cvv}\n")
          with open('database/cardFailed.txt', 'a') as ae:
             ae.write(f"{self.ccn}:{self.expM}:{self.expY}:{self.cvv}\n")
          with open('database/failedDatabaseWithErrors.txt', 'a') as fs:
             fs.write(f"{self.token}:{self.ccn}:{self.expM}:{self.expY}:{self.cvv} -> JSON RESPONSE: {response.json()}\n")
          return 'F'
       header4 = {
    'authority': 'api.stripe.com',
    'accept': 'application/json',
    'accept-language': 'en-US,en;q=0.9',
    'content-type': 'application/x-www-form-urlencoded',
    'origin': 'https://js.stripe.com',
    'referer': 'https://js.stripe.com/',
    'sec-ch-ua': '"Chromium";v="122", "Not(A:Brand";v="24", "Microsoft Edge";v="122"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'empty',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'same-site',
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0',
}
       data = f'payment_method_data[type]=card&payment_method_data[card][token]={TokenCard}&payment_method_data[billing_details][address][line1]={line_1}&payment_method_data[billing_details][address][line2]=&payment_method_data[billing_details][address][city]={city}&payment_method_data[billing_details][address][state]={state}&payment_method_data[billing_details][address][postal_code]={postalcode}&payment_method_data[billing_details][address][country]={country}&payment_method_data[billing_details][name]={cardName}&payment_method_data[guid]={uuid.uuid4()}&payment_method_data[muid]={uuid.uuid4()}&payment_method_data[sid]={uuid.uuid4()}&payment_method_data[payment_user_agent]=stripe.js%2F28b7ba8f85%3B+stripe-js-v3%2F28b7ba8f85&payment_method_data[referrer]=https%3A%2F%2Fdiscord.com&payment_method_data[time_on_page]=707159&expected_payment_method_type=card&use_stripe_sdk=true&key=pk_live_CUQtlpQUF0vufWpnpUmQvcdi&client_secret={csTok}'
       response = sT.post(
    f'https://api.stripe.com/v1/setup_intents/{Stok}/confirm',
    headers=header4,
    data=data, proxy=self.proxy
)
       try:
          CardSCMAIN = response.json()["id"]
          pmTok = response.json()["payment_method"]
       except Exception as e:
          Eprint(f'{Fore.LIGHTRED_EX}[ERROR] {Fore.LIGHTMAGENTA_EX}- {Fore.LIGHTCYAN_EX}Failed Adding Card 574')
          failed += 1
          send_discord_webhook(wurl)
          set_console_title()
          with open('outputFails/failedPromos.txt', 'a') as sp:
             sp.write(f"{self.promoz}\n")
          with open('outputFails/failedTokens.txt', 'a') as st:
             st.write(f"{self.token}\n")
          with open('outputFails/failedVccs.txt', 'a') as sv:
             sv.write(f"{self.ccn}:{self.expM}:{self.expY}:{self.cvv}\n")
          with open('database/cardFailed.txt', 'a') as ae:
             ae.write(f"{self.ccn}:{self.expM}:{self.expY}:{self.cvv}\n")
          with open('database/failedDatabaseWithErrors.txt', 'a') as fs:
             fs.write(f"{self.token}:{self.ccn}:{self.expM}:{self.expY}:{self.cvv} -> JSON RESPONSE: {response.json()}\n")
          return 'F'
       header5 = {
    'authority': 'discord.com',
    'accept': '*/*',
    'accept-language': 'en-US,en;q=0.9',
    'authorization': self.token,
    'content-type': 'application/json',
    'origin': 'https://discord.com',
    'referer': 'https://discord.com/channels/@me',
    'sec-ch-ua': '"Chromium";v="122", "Not(A:Brand";v="24", "Microsoft Edge";v="122"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'empty',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'same-origin',
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0',
    'x-debug-options': 'bugReporterEnabled',
    'x-discord-locale': 'en-US',
    'x-discord-timezone': 'Europe/Budapest',
    'x-super-properties': 'eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiQ2hyb21lIiwiZGV2aWNlIjoiIiwic3lzdGVtX2xvY2FsZSI6ImVuLVVTIiwiYnJvd3Nlcl91c2VyX2FnZW50IjoiTW96aWxsYS81LjAgKFdpbmRvd3MgTlQgMTAuMDsgV2luNjQ7IHg2NCkgQXBwbGVXZWJLaXQvNTM3LjM2IChLSFRNTCwgbGlrZSBHZWNrbykgQ2hyb21lLzEyMi4wLjAuMCBTYWZhcmkvNTM3LjM2IEVkZy8xMjIuMC4wLjAiLCJicm93c2VyX3ZlcnNpb24iOiIxMjIuMC4wLjAiLCJvc192ZXJzaW9uIjoiMTAiLCJyZWZlcnJlciI6IiIsInJlZmVycmluZ19kb21haW4iOiIiLCJyZWZlcnJlcl9jdXJyZW50IjoiIiwicmVmZXJyaW5nX2RvbWFpbl9jdXJyZW50IjoiIiwicmVsZWFzZV9jaGFubmVsIjoic3RhYmxlIiwiY2xpZW50X2J1aWxkX251bWJlciI6MjY4NjAwLCJjbGllbnRfZXZlbnRfc291cmNlIjpudWxsfQ==',
}
       jsonD2 = {
    'payment_gateway': 1,
    'token': pmTok,
    'billing_address': {
        'name': cardName,
        'line_1': line_1,
        'line_2': None,
        'city': city,
        'state': state,
        'postal_code': postalcode,
        'country': country,
        'email': '',
    },
    'billing_address_token': BTok
}
       response = sT.post(
    'https://discord.com/api/v9/users/@me/billing/payment-sources',
    headers=header5,
    json=jsonD2
)
       try:
          purchaseId = response.json()["id"]
          Iprint()
          return purchaseId
       except Exception as e:
          if 'captcha_key' in str(response.json()):
            Eprint(f'{Fore.LIGHTRED_EX}[ERROR] {Fore.LIGHTMAGENTA_EX}- {Fore.LIGHTCYAN_EX}Failed Adding Card {Fore.YELLOW}(Captcha-Detected)')
            if cIsOn == 'yes':
               c = self.get_soln()
               header6 ={ 
    'authority': 'discord.com',
    'accept': '*/*',
    'accept-language': 'en-US,en;q=0.9',
    'authorization': self.token,
    'content-type': 'application/json',
    'origin': 'https://discord.com',
    'referer': 'https://discord.com/channels/@me',
    'sec-ch-ua': '"Chromium";v="122", "Not(A:Brand";v="24", "Microsoft Edge";v="122"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'empty',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'same-origin',
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0',
    'x-captcha-key': c,
    'x-captcha-rqtoken': str(response.json()["captcha_rqdata"]),
    'x-debug-options': 'bugReporterEnabled',
    'x-discord-locale': 'en-US',
    'x-discord-timezone': 'Europe/Budapest',
    'x-super-properties': 'eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiQ2hyb21lIiwiZGV2aWNlIjoiIiwic3lzdGVtX2xvY2FsZSI6ImVuLVVTIiwiYnJvd3Nlcl91c2VyX2FnZW50IjoiTW96aWxsYS81LjAgKFdpbmRvd3MgTlQgMTAuMDsgV2luNjQ7IHg2NCkgQXBwbGVXZWJLaXQvNTM3LjM2IChLSFRNTCwgbGlrZSBHZWNrbykgQ2hyb21lLzEyMi4wLjAuMCBTYWZhcmkvNTM3LjM2IEVkZy8xMjIuMC4wLjAiLCJicm93c2VyX3ZlcnNpb24iOiIxMjIuMC4wLjAiLCJvc192ZXJzaW9uIjoiMTAiLCJyZWZlcnJlciI6IiIsInJlZmVycmluZ19kb21haW4iOiIiLCJyZWZlcnJlcl9jdXJyZW50IjoiIiwicmVmZXJyaW5nX2RvbWFpbl9jdXJyZW50IjoiIiwicmVsZWFzZV9jaGFubmVsIjoic3RhYmxlIiwiY2xpZW50X2J1aWxkX251bWJlciI6MjY4NjAwLCJjbGllbnRfZXZlbnRfc291cmNlIjpudWxsfQ==',
               }
               p2 = {
    'payment_gateway': 1,
    'token': pmTok,
    'billing_address': {
        'name': cardName,
        'line_1': line_1,
        'line_2': None,
        'city': city,
        'state': state,
        'postal_code': postalcode,
        'country': country,
        'email': '',
    },
    'billing_address_token': BTok
}
               responsea = sT.post(
    'https://discord.com/api/v9/users/@me/billing/payment-sources',
    headers=header6,
    json=p2
)
               if responsea.status_code == 200:
                  Iprint()
               else:
                  Eprint(f'{Fore.LIGHTRED_EX}[ERROR] {Fore.LIGHTMAGENTA_EX}- {Fore.LIGHTCYAN_EX}Failed Solving Posting Captcha Key In Discord API Header')
            else:
               pass
               
            with open('database/captchaTokens.txt', 'a') as es:
               es.write(f"{self.token} -> Captcha Required.\n")
          else:
            Eprint(f'{Fore.LIGHTRED_EX}[ERROR] {Fore.LIGHTMAGENTA_EX}- {Fore.LIGHTCYAN_EX}Failed Adding Card 633')
          with open('outputFails/failedPromos.txt', 'a') as sp:
             sp.write(f"{self.promoz}\n")
          with open('outputFails/failedTokens.txt', 'a') as st:
             st.write(f"{self.token}\n")
          with open('outputFails/failedVccs.txt', 'a') as sv:
             sv.write(f"{self.ccn}:{self.expM}:{self.expY}:{self.cvv}\n")
          with open('database/cardFailed.txt', 'a') as ae:
             ae.write(f"{self.ccn}:{self.expM}:{self.expY}:{self.cvv}\n")
          with open('database/failedDatabaseWithErrors.txt', 'a') as fs:
             fs.write(f"{self.token}:{self.ccn}:{self.expM}:{self.expY}:{self.cvv} -> JSON RESPONSE: {response.json()}\n")
          failed += 1
          send_discord_webhook(wurl)
          set_console_title()
          return 'F'
def nameChanger(token: str, dName: str):
    headers = {
    'authority': 'discord.com',
    'accept': '*/*',
    'accept-language': 'en-US,en;q=0.9',
    'authorization': token,
    'content-type': 'application/json',
    # 'cookie': '__dcfduid=3aa2e550d88811ee8ebe6f2ec480765f; __sdcfduid=3aa2e551d88811ee8ebe6f2ec480765f52ad3c70d6fba937f26437b3b34748f837ede062b02e78b1857ee3dd206fe25c; __cfruid=8705d1991b6d5ce8ce8fc1123e62dfdd307415df-1709379010; _cfuvid=mkce45BcHN47tPvNUq2inSfswqa99yPxlYHXxJdsLrs-1709379010600-0.0.1.1-604800000; cf_clearance=Zzc_p_LPCf3jUlQP4xgL4haLaDvcTFdAWBlrFtJSnF0-1709379013-1.0.1.1-Ore_ztu.aA6E0JQ7T7BV1jq4fcz.zj2Z.f99Pt0Jz.OiLAAEnhp9gCIQF1GeGB9X3NwxloqetlsWGiU_6TwlQg',
    'origin': 'https://discord.com',
    'referer': 'https://discord.com/channels/@me',
    'sec-ch-ua': '"Chromium";v="122", "Not(A:Brand";v="24", "Microsoft Edge";v="122"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'empty',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'same-origin',
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0',
    'x-debug-options': 'bugReporterEnabled',
    'x-discord-locale': 'en-US',
    'x-discord-timezone': 'Europe/Budapest',
    'x-super-properties': 'eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiQ2hyb21lIiwiZGV2aWNlIjoiIiwic3lzdGVtX2xvY2FsZSI6ImVuLVVTIiwiYnJvd3Nlcl91c2VyX2FnZW50IjoiTW96aWxsYS81LjAgKFdpbmRvd3MgTlQgMTAuMDsgV2luNjQ7IHg2NCkgQXBwbGVXZWJLaXQvNTM3LjM2IChLSFRNTCwgbGlrZSBHZWNrbykgQ2hyb21lLzEyMi4wLjAuMCBTYWZhcmkvNTM3LjM2IEVkZy8xMjIuMC4wLjAiLCJicm93c2VyX3ZlcnNpb24iOiIxMjIuMC4wLjAiLCJvc192ZXJzaW9uIjoiMTAiLCJyZWZlcnJlciI6IiIsInJlZmVycmluZ19kb21haW4iOiIiLCJyZWZlcnJlcl9jdXJyZW50IjoiIiwicmVmZXJyaW5nX2RvbWFpbl9jdXJyZW50IjoiIiwicmVsZWFzZV9jaGFubmVsIjoic3RhYmxlIiwiY2xpZW50X2J1aWxkX251bWJlciI6MjcxMjE2LCJjbGllbnRfZXZlbnRfc291cmNlIjpudWxsfQ==',
}
    json_data = {
    'global_name': str(dName),
}

    response = sT.patch('https://discord.com/api/v9/users/@me', headers=headers, json=json_data)
    if response.status_code == 200:
        return
    else:
        return

def redemption_process(token, vcc, promo, proxy):
    instance = REDEEMER(token, vcc, promo, proxy)
    card = instance.AddCard()
    if not card == 'F':
        Ruanner = instance.RedeemPromo(card)
        if Ruanner == 'Ar':
            print('Authentication required, stopping threads.')
            return
    else:
        return

def fetch_proxies():
    proxies = []
    with open('proxies.txt', 'r') as f:
        for line in f:
            proxies.append(line.strip())
    return proxies

def main():
    num_threads = int(input(f"{Fore.LIGHTWHITE_EX}[{Fore.LIGHTBLACK_EX}{format_current_time()}{Fore.LIGHTWHITE_EX}]  {Fore.LIGHTWHITE_EX}[{Fore.LIGHTMAGENTA_EX}?{Fore.LIGHTWHITE_EX}] {Fore.LIGHTCYAN_EX} Enter the number of threads: "))
    os.system('cls')

    proxies = fetch_proxies() if sj == 'on' else [None] * num_threads

    with open('input/tokens.txt') as f_tokens, \
            open('input/vccs.txt') as f_vccs, \
            open('input/promos.txt') as f_promos:

        lines_tokens = f_tokens.readlines()
        lines_vccs = f_vccs.readlines()
        lines_promos = f_promos.readlines()

        threads = []
        i = 0

        while True:
            if i >= len(lines_tokens):
                break

            token = lines_tokens[i].strip()
            vcc = lines_vccs[i % len(lines_vccs)].strip()

            if ipg == 'on':
                promo = Opera().gen()
            else:
                promo = lines_promos[i % len(lines_promos)].strip()

            proxy = proxies[i % len(proxies)]

            thread = threading.Thread(target=redemption_process, args=(token, vcc, promo, proxy))
            thread.start()
            threads.append(thread)

            i += 1

            if len(threads) >= num_threads or i >= max(len(lines_tokens), len(lines_vccs), len(lines_promos)):
                for thread in threads:
                    thread.join()
                threads = []

                for token in lines_tokens:
                    nameChanger(token.strip(), dName.strip())

if __name__ == "__main__":
    main()
    Cprint(Fore.LIGHTBLUE_EX, '@', f'{Fore.LIGHTMAGENTA_EX}[INFO] {Fore.LIGHTMAGENTA_EX} - {Fore.LIGHTCYAN_EX}Materials completed, Claimed={claimed}, Failed={failed}, Processed={processed}.')
    input(f'{Fore.LIGHTWHITE_EX}[{Fore.LIGHTBLACK_EX}{format_current_time()}{Fore.LIGHTWHITE_EX}]  {Fore.LIGHTWHITE_EX}[{Fore.LIGHTGREEN_EX}?{Fore.LIGHTWHITE_EX}]  {Fore.LIGHTBLUE_EX}[INPUT] {Fore.LIGHTMAGENTA_EX}- {Fore.LIGHTWHITE_EX}[{Fore.LIGHTMAGENTA_EX}?{Fore.LIGHTWHITE_EX}] {Fore.LIGHTCYAN_EX} Press enter to exit : ')
