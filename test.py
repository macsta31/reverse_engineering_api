import time
import signal
import requests

def test(n):
    try:
        urls = [
            "https://www.superdataminer.com/posts/66cff907ce8e",
            "https://www.superdataminer.com/posts/f21878c9897",
            "https://www.superdataminer.com/posts/b24dec228c43",
            "https://www.superdataminer.com/posts/b24dec228c43",
            "https://www.superdataminer.com/posts/b24dec228c43",
        ]
        
        for url in urls:
            try:
                res = requests.get(url, timeout=10)
                print(len(res.content),"=>>>Length")
            except requests.exceptions.Timeout as err:
                # Don't handle the exception here; let it propagate to the caller.
                raise
            except ConnectionError as err:
                print(err,"=>>Request error")
                print(err.__class__.__name__)
                break
                pass

        if n/7==1.0:
            print(10/0)
        print(f"{n} iteration done")
    except Exception as e:
        print(e.__class__.__name__)
        pass

def timeout_handler(signum, frame):
    raise TimeoutError("Timeout occurred")

start_time = time.time()  # Start time before the operations

try:
    signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(10)
    
    for i in range(1,20):
        elapsed_time = time.time() - start_time
        print(f"Elapsed time: {elapsed_time} seconds")
        if elapsed_time >= 20:
            print("Timeout!")
            break
        try:
            test(i)
        except requests.exceptions.Timeout as err:
            print(err)
            break
except requests.exceptions.Timeout:
    print("A timeout occurred during one of the requests.")
