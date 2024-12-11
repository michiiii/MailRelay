#! /usr/bin/env python
"""
Small script for testing open mail relays. 

You should always test if internal users can send emails to:
- other internal users
- external users

"""
from __future__ import print_function
import sys
import argparse
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email import encoders
from email.mime.base import MIMEBase
from os.path import basename
from email.mime.application import MIMEApplication
import dns.resolver


class bcolors:
    OK = '\033[92m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'

def main():
   args = parse_args()

   sender_email = args.sender_email
   sender_domain = sender_email.split('@')[1]
   receiver_email = args.receiver_email
   contact_email = args.contact
   starttls = False
   port = 25

   if args.ssl:
    starttls = True

   if args.port:
    port = args.port

   with open(args.filename) as file:
    smtpservers = file.readlines()
    smtpservers = [smtpserver.rstrip() for smtpserver in smtpservers]

    ### Checking SPF
    print()
    print ("Testing domain", sender_domain, "for SPF record...")
    try:
        test_spf = dns.resolver.resolve(sender_domain , 'TXT')
        for dns_data in test_spf:
            if 'spf1' in str(dns_data) and '-all' in str(dns_data):
                print (bcolors.OK + "  [PASS] Strict SPF record found   :"+ bcolors.ENDC,dns_data)
            elif 'spf1' in str(dns_data) and '~all' in str(dns_data):
                print (bcolors.OK + "  [PASS] Moderate SPF record found   :"+ bcolors.ENDC,dns_data)
            elif 'spf1' in str(dns_data) and '+all' in str(dns_data):
                print (bcolors.FAIL + "  [FAIL] Lax SPF record found   :"+ bcolors.ENDC,dns_data)                
    except:
        print (bcolors.FAIL + "  [FAIL] SPF record not found."+ bcolors.ENDC)
        pass

    ### Checking DMARC
    print()
    print ("Testing domain", sender_domain, "for DMARC record...")
    try:
        test_dmarc = dns.resolver.resolve('_dmarc.' + sender_domain , 'TXT')
        for dns_data in test_dmarc:
            if 'DMARC1' in str(dns_data) and 'p=reject' in str(dns_data):
                print (bcolors.OK + "  [PASS] Strict DMARC record found :"+ bcolors.ENDC,dns_data)
            elif 'DMARC1' in str(dns_data) and 'p=quarantine' in str(dns_data):
                print (bcolors.OK + "  [PASS] Moderate DMARC record found :"+ bcolors.ENDC,dns_data)
            elif 'DMARC1' in str(dns_data) and 'p=none' in str(dns_data):
                print (bcolors.FAIL + "  [FAIL] Lax DMARC record found :"+ bcolors.ENDC,dns_data)

    except:
        print (bcolors.FAIL + "  [FAIL] DMARC record not found." + bcolors.ENDC)
        pass    


   for smtpserver in smtpservers:
      message = MIMEMultipart("alternative")
      message["Subject"] = "Proof-of-Concept // Insecure Mail Relay on "+ smtpserver
      message["From"] = sender_email
      message["To"] = receiver_email

      # Create HTML version of your message
      text = """\
      <html>
         <style>
            .content {
            font-family: Calibri;
            }
         </style>
         <body>
            <div class='content'>
               <p>Dears,</p>
               <p>if you receive this email, your SMTP server is vulnerable to<strong> Open Mail Relay</strong>.</p>
               <p>Alternatively, you have not correctly configured Sender Policy Framework (SPF) and Domain-based Message Authentication, Reporting & Conformance (DMARC).</p>
               <p> Affected SMTP Server: """ + smtpserver + """</p>
               <p>Please forward this email to """ + contact_email + """</p>
               <p></p>         
               <p>Have a good day</p>         
         
               <br>
            </div>
         </body>
      </html>
      """

      # Turn these into html MIMEText objects
      part1 = MIMEText(text, "html")

      # Add HTML parts to MIMEMultipart message
      # The email client will try to render the last part first
      message.attach(part1)

      # Encode file in ASCII characters to send by email    
      encoders.encode_base64(part1)

      # Add attachment to message and convert message to string
      # message.attach(part)
      text = message.as_string()
      print()

      try:
        if starttls:      
         with smtplib.SMTP(smtpserver, port) as server:
             context = ssl._create_unverified_context(ssl.PROTOCOL_TLS_CLIENT)
             server.ehlo()
             server.starttls(context=context)
             server.ehlo()
             server.sendmail(sender_email, receiver_email, message.as_string())
             print(bcolors.OK + "[i] Mail Relay tested on: " + smtpserver + ":" + str(port) + bcolors.ENDC)
        else:
         with smtplib.SMTP(smtpserver, port) as server:
             server.sendmail(sender_email, receiver_email, message.as_string())
             print(bcolors.OK + "[i] Mail Relay tested on: " + smtpserver + ":" + str(port) + bcolors.ENDC)
      except Exception as e:
        print(bcolors.FAIL + "[!] Mail Relay failed on: " + smtpserver + ":" + str(port) + bcolors.ENDC)
        print(bcolors.FAIL + "    > " + str(e) + bcolors.ENDC)
        print()
        continue

def parse_args():
    format = "%(levelname)s :: %(message)s"
    parser = argparse.ArgumentParser(description="Open Relay tester")
    parser.add_argument(
        "--receiver",
        help="Receiver of the mail",
        dest="receiver_email",
        type=str,
        required=True
    )
    parser.add_argument(
        "--sender",
        help="Sender of the mail",
        dest="sender_email",
        type=str,
        required=True
    )
    parser.add_argument(
        "--targets",
        help="File with SMTP servers to test",
        dest="filename",
        type=str,
        required=True
    ) 
    parser.add_argument(
        "--contact",
        help="E-Mail address to forward the mail to",
        dest="contact",
        type=str,
        required=True
    ) 
    parser.add_argument(
        "--port",
        help="SMTP port to connect to",
        dest="port",
        type=int,
        required=False
    ) 
    parser.add_argument(
        "--ssl",
        help="Whether to use SMTP_SSL or not",
        dest="ssl",
        action='store_true',
        required=False
    )      

    args = parser.parse_args()
    return args

if __name__ == "__main__":
    main()
