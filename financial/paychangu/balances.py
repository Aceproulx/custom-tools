from concurrent.futures import ThreadPoolExecutor
import threading
import requests

URL = "https://api.paychangu.com/wallet-balance"
PARAMS = {"currency": "MWK"}
MAX_WORKERS = 10

thread_local = threading.local()
print_lock = threading.Lock()


def get_session():
    if not hasattr(thread_local, "session"):
        thread_local.session = requests.Session()
    return thread_local.session


def fetch_balance(api_key: str):
    session = get_session()
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Accept": "application/json",
    }

    try:
        response = session.get(URL, params=PARAMS, headers=headers, timeout=60)
        response.raise_for_status()

        payload = response.json()
        data = payload.get("data", {})
        currency = data.get("currency", "MWK")
        main_bal = data.get("main_balance", 0)
        coll_bal = data.get("collection_balance", 0)

        # Thread-safe clean print block
        with print_lock:
            print(f"API Key: {api_key}")
            print(f"  ├─ Main Balance:       {main_bal:,.2f} {currency}")
            print(f"  └─ Collection Balance: {coll_bal:,.2f} {currency}")
            print("-" * 45)

    except requests.exceptions.RequestException as e:
        with print_lock:
            print(f"API Key: {api_key}")
            print(f"  └─ [Error] Request failed: {e}")
            print("-" * 45)
    except ValueError:
        with print_lock:
            print(f"API Key: {api_key}")
            print(f"  └─ [Error] Non-JSON response: {response.text}")
            print("-" * 45)


def main():
    with open("apikeys.txt", "r", encoding="utf-8") as f:
        keys = [line.strip() for line in f if line.strip()]

    print(f"Checking balances for {len(keys)} key(s)...\n" + "=" * 45)

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        executor.map(fetch_balance, keys)


if __name__ == "__main__":
    main()
