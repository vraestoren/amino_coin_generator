import logging
from json import load
from time import time, sleep
from src.wrapper.amino import Amino
from concurrent.futures import ThreadPoolExecutor

logging.basicConfig(
    level=logging.INFO, format="[%(asctime)s] [%(levelname)s] %(message)s")
logger = logging.getLogger()

with open("accounts.json") as file:
    accounts = load(file)

def get_timers() -> dict:
    return {"start": int(time()), "end": int(time()) + 300}

def login(
        client: Amino, email: str, password: str) -> None:
    try:
        client.login(
            email=email, password=password, socket=False)
        logger.info(f"Logged in: {email}")
    except Exception as exception:
        logger.error(f"Login failed for {email}: {exception}")

def generate_coins(
        client: Amino, ndc_id: int, email: str) -> None:
    timers = [get_timers() for _ in range(50)]
    client.send_active_object(ndc_id=ndc_id, timers=timers)
    logger.info(f"Generating coins for: {email}")

def play_lottery(client: Amino, ndc_id: int) -> None:
    try:
        response = client.lottery(ndc_id=ndc_id)["api:message"]
        logger.info(f"Lottery result: {response}")
    except Exception as exception:
        logger.error(f"Lottery error: {exception}")

def watch_ad(client: Amino) -> None:
    try:
        response = client.watch_ad()["api:message"]
        logger.info(f"Ad watched: {response}")
    except Exception as exception:
        logger.error(f"Ad watch error: {exception}")

def send_coins(client: Amino) -> None: 
    link_info = client.get_from_code(
        input("Blog link: "))["linkInfoV2"]["extensions"]["linkInfo"]
    ndc_id, blog_id = link_info["ndcId"], link_info["objectId"]
    for account in accounts:
        account_client = Amino()
        email = account["email"]
        password = account["password"]
        try:
            login(
                client=account_client, email=email, password=password)
            account_client.join_community(ndc_id=ndc_id)
            total_coins = account_client.get_wallet_info()["wallet"]["totalCoins"]
            logger.info(f"{email} has {total_coins} coins")
            amount = min(total_coins, 500)
            if amount > 0:
                response = account_client.send_coins_blog(
                    ndc_id=ndc_id, blog_Id=blog_id, coins=amount)["api:message"]
                logger.info(f"Sent {amount} coins | Response: {response}")
        except Exception as exception:
            logger.error(f"Failed to send coins: {exception}")

def start(init_client: Amino) -> None: # как протрезвеешь подумай об этом - Крист.
    ndc_id = init_client.get_from_code(
        input("Community link: "))["linkInfoV2"]["extensions"]["community"]["ndcId"]
    delay = int(input("Generation delay in seconds: "))
    for account in accounts:
        account_client = Amino()
        email = account["email"]
        password = account["password"]
        try:
            login(
                client=account_client, email=email, password=password)
            watch_ad(client=account_client)
            play_lottery(client=account_client, ndc_id=ndc_id)
            with ThreadPoolExecutor(max_workers=10) as executor:
                for _ in range(25):
                    executor.submit(generate_coins, account_client, ndc_id, email)
            sleep(delay)
        except Exception as exception:
            logger.error(f"Error in main process {exception}")
