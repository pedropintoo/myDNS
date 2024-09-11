# Simple DNS home server

* `zones/*.zone` - zone files
* `dns.py` - run local dns server

## Run the micro server
In order to run the dns server, run the following command: (sudo is required to use port 53 - default dns port)
```sh
sudo python3 dns.py
```

## DNS requests/responses
In other terminal, in order to test the dns server, run the following command:
```sh
dig teste.com @127.0.0.1
```
```sh
dig howcode.org @127.0.0.1
```