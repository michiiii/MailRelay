# MailRelay
a little python script to test SMTP servers for relay weaknesses

Small script for testing open mail relays. 

You should always test if internal users can send emails to:
- other internal users
- external users

```
usage: MailRelay.py [-h] --receiver RECEIVER_EMAIL --sender SENDER_EMAIL --targets FILENAME --contact CONTACT

Open Relay tester

options:
  -h, --help            show this help message and exit
  --receiver RECEIVER_EMAIL
                        Receiver of the mail
  --sender SENDER_EMAIL
                        Sender of the mail
  --targets FILENAME    File with SMTP servers to test
  --contact CONTACT     E-Mail address to forward the mail to
```

