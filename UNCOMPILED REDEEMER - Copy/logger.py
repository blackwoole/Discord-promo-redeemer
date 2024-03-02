from colorama import Fore, Style
import datetime
import random
import json
def format_current_time():
    current_time = datetime.datetime.now()
    formatted_time = current_time.strftime("%H:%M:%S")
    return formatted_time
with open('config.json', 'r') as f:
   config = json.load(f)
promoType = config["promoType"]
def Dprint(content: str):
    print(f"{Fore.LIGHTWHITE_EX}[{Style.BRIGHT + Fore.LIGHTBLACK_EX}{format_current_time()}{Fore.LIGHTWHITE_EX}]  [{Style.BRIGHT + Fore.LIGHTGREEN_EX}${Fore.LIGHTWHITE_EX}]  {Style.BRIGHT + Fore.LIGHTWHITE_EX}{content}{Style.RESET_ALL}")
def Sprint(token: str):
    print(f"{Fore.LIGHTWHITE_EX}[{Style.BRIGHT + Fore.LIGHTBLACK_EX}{format_current_time()}{Fore.LIGHTWHITE_EX}]  [{Style.BRIGHT + Fore.LIGHTGREEN_EX}${Fore.LIGHTWHITE_EX}]  {Fore.LIGHTBLUE_EX}[REDEEMED] {Fore.LIGHTMAGENTA_EX}- {Fore.LIGHTGREEN_EX}No captcha detected {Style.BRIGHT + Fore.LIGHTCYAN_EX}token -> {token}")
def Eprint(content: str):
    print(f"{Fore.LIGHTWHITE_EX}[{Style.BRIGHT + Fore.LIGHTBLACK_EX}{format_current_time()}{Fore.LIGHTWHITE_EX}]  [{Style.BRIGHT + Fore.LIGHTGREEN_EX}¿{Fore.LIGHTWHITE_EX}]  {Style.BRIGHT + Fore.LIGHTCYAN_EX}{content}")

def Wprint(content: str):
    print(f"{Fore.LIGHTWHITE_EX}[{Style.BRIGHT + Fore.LIGHTBLACK_EX}{format_current_time()}{Fore.LIGHTWHITE_EX}]  [{Style.BRIGHT + Fore.LIGHTGREEN_EX}!{Fore.LIGHTWHITE_EX}]  {Style.BRIGHT + Fore.LIGHTCYAN_EX}{content}")
def Aprint(vcc: str):
    print(f"{Fore.LIGHTWHITE_EX}[{Style.BRIGHT + Fore.LIGHTBLACK_EX}{format_current_time()}{Fore.LIGHTWHITE_EX}]{Style.BRIGHT + Fore.LIGHTBLUE_EX}  {Fore.LIGHTWHITE_EX}[{Style.BRIGHT + Fore.LIGHTGREEN_EX}${Fore.LIGHTWHITE_EX}]  {Fore.LIGHTBLUE_EX}[Adding Card] {Fore.LIGHTMAGENTA_EX}- {Style.BRIGHT + Fore.LIGHTCYAN_EX}card -> {vcc}")
def Iprint():
    print(f"{Fore.LIGHTWHITE_EX}[{Style.BRIGHT + Fore.LIGHTBLACK_EX}{format_current_time()}{Fore.LIGHTWHITE_EX}]{Style.BRIGHT + Fore.LIGHTBLUE_EX}  {Fore.LIGHTWHITE_EX}[{Style.BRIGHT + Fore.LIGHTGREEN_EX}${Fore.LIGHTWHITE_EX}]  {Fore.LIGHTBLUE_EX}[Added Card] {Fore.LIGHTMAGENTA_EX}- {Style.BRIGHT + Fore.LIGHTCYAN_EX}Redeeming promo = {promoType}")

def Uprint():
    print(f"{Fore.LIGHTWHITE_EX}[{Style.BRIGHT + Fore.LIGHTBLACK_EX}{format_current_time()}{Fore.LIGHTWHITE_EX}]{Style.BRIGHT + Fore.LIGHTBLUE_EX}  {Fore.LIGHTWHITE_EX}[{Style.BRIGHT + Fore.LIGHTGREEN_EX}${Fore.LIGHTWHITE_EX}]  {Fore.LIGHTBLUE_EX}[Card] {Fore.LIGHTMAGENTA_EX}- {Style.BRIGHT + Fore.LIGHTCYAN_EX}Successfully removed card")
def Cprint(color, tag, content: str):
    print(f"{Fore.LIGHTWHITE_EX}[{Style.BRIGHT + Fore.LIGHTBLACK_EX}{format_current_time()}{Fore.LIGHTWHITE_EX}]  {Style.BRIGHT + color}[{tag}]  {Style.BRIGHT + Fore.LIGHTCYAN_EX}{content}{Style.RESET_ALL}")