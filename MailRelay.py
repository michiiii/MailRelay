#!/usr/bin/env python3
"""
SMTP Open Relay Tester

Tests SMTP servers for open relay vulnerabilities and checks SPF/DMARC configurations.

Usage:
    python smtp_relay_tester.py --sender test@example.com --receiver victim@example.com --contact security@example.com --targets servers.txt

Targets file format (one per line):
    mail.example.com
    mail.example.com:587
    mail.example.com:465:ssl
    mail.example.com:25:starttls
"""

import sys
import argparse
import smtplib
import ssl
import socket
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email import encoders
import dns.resolver


class Colors:
    """ANSI color codes for terminal output"""
    OK = '\033[92m'
    WARN = '\033[93m'
    FAIL = '\033[91m'
    INFO = '\033[94m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'


def print_banner():
    """Print script banner"""
    print(f"\n{Colors.BOLD}{'='*70}")
    print("SMTP Open Relay Tester")
    print(f"{'='*70}{Colors.ENDC}\n")


def check_spf(domain):
    """Check SPF record for domain"""
    print(f"\n{Colors.INFO}[*] Checking SPF record for {domain}...{Colors.ENDC}")
    try:
        records = dns.resolver.resolve(domain, 'TXT')
        spf_found = False
        
        for record in records:
            record_str = str(record)
            if 'v=spf1' in record_str.lower():
                spf_found = True
                if '-all' in record_str:
                    print(f"{Colors.OK}    [PASS] Strict SPF (-all): {record}{Colors.ENDC}")
                elif '~all' in record_str:
                    print(f"{Colors.OK}    [PASS] Soft fail SPF (~all): {record}{Colors.ENDC}")
                elif '?all' in record_str:
                    print(f"{Colors.WARN}    [WARN] Neutral SPF (?all): {record}{Colors.ENDC}")
                elif '+all' in record_str:
                    print(f"{Colors.FAIL}    [FAIL] Permissive SPF (+all): {record}{Colors.ENDC}")
                else:
                    print(f"{Colors.WARN}    [WARN] SPF found: {record}{Colors.ENDC}")
        
        if not spf_found:
            print(f"{Colors.FAIL}    [FAIL] No SPF record found{Colors.ENDC}")
            
    except dns.resolver.NXDOMAIN:
        print(f"{Colors.FAIL}    [FAIL] Domain does not exist{Colors.ENDC}")
    except dns.resolver.NoAnswer:
        print(f"{Colors.FAIL}    [FAIL] No TXT records found{Colors.ENDC}")
    except Exception as e:
        print(f"{Colors.FAIL}    [FAIL] Error checking SPF: {e}{Colors.ENDC}")


def check_dmarc(domain):
    """Check DMARC record for domain"""
    print(f"\n{Colors.INFO}[*] Checking DMARC record for {domain}...{Colors.ENDC}")
    try:
        records = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
        
        for record in records:
            record_str = str(record)
            if 'v=DMARC1' in record_str or 'v=dmarc1' in record_str.lower():
                if 'p=reject' in record_str.lower():
                    print(f"{Colors.OK}    [PASS] Strict DMARC (reject): {record}{Colors.ENDC}")
                elif 'p=quarantine' in record_str.lower():
                    print(f"{Colors.OK}    [PASS] Moderate DMARC (quarantine): {record}{Colors.ENDC}")
                elif 'p=none' in record_str.lower():
                    print(f"{Colors.WARN}    [WARN] Monitoring DMARC (none): {record}{Colors.ENDC}")
                else:
                    print(f"{Colors.WARN}    [WARN] DMARC found: {record}{Colors.ENDC}")
                    
    except dns.resolver.NXDOMAIN:
        print(f"{Colors.FAIL}    [FAIL] No DMARC record found{Colors.ENDC}")
    except dns.resolver.NoAnswer:
        print(f"{Colors.FAIL}    [FAIL] No DMARC record found{Colors.ENDC}")
    except Exception as e:
        print(f"{Colors.FAIL}    [FAIL] Error checking DMARC: {e}{Colors.ENDC}")


def parse_target_line(line):
    """
    Parse target line from file.
    
    Format: hostname[:port[:mode]]
    Examples:
        mail.example.com
        mail.example.com:587
        mail.example.com:465:ssl
        mail.example.com:25:starttls
        mail.example.com:25:plain
    
    Returns: (hostname, port, mode)
    """
    parts = line.strip().split(':')
    hostname = parts[0]
    port = 25  # default
    mode = 'auto'  # auto-detect
    
    if len(parts) >= 2:
        try:
            port = int(parts[1])
        except ValueError:
            print(f"{Colors.WARN}[!] Invalid port in '{line}', using default 25{Colors.ENDC}")
    
    if len(parts) >= 3:
        mode = parts[2].lower()
        if mode not in ['auto', 'ssl', 'starttls', 'plain']:
            print(f"{Colors.WARN}[!] Invalid mode '{mode}' in '{line}', using auto{Colors.ENDC}")
            mode = 'auto'
    
    return hostname, port, mode


def test_smtp_connection(hostname, port, mode='auto'):
    """
    Test SMTP connection and determine best connection method.
    
    Returns: (success, connection_mode, server_object or None)
    """
    # If mode is specified, use it
    if mode == 'ssl':
        try:
            context = ssl.create_default_context()
            server = smtplib.SMTP_SSL(hostname, port, timeout=10, context=context)
            server.ehlo()
            return True, 'ssl', server
        except Exception as e:
            return False, 'ssl', None
    
    elif mode == 'starttls':
        try:
            server = smtplib.SMTP(hostname, port, timeout=10)
            server.ehlo()
            context = ssl.create_default_context()
            server.starttls(context=context)
            server.ehlo()
            return True, 'starttls', server
        except Exception as e:
            return False, 'starttls', None
    
    elif mode == 'plain':
        try:
            server = smtplib.SMTP(hostname, port, timeout=10)
            server.ehlo()
            return True, 'plain', server
        except Exception as e:
            return False, 'plain', None
    
    # Auto-detect mode
    # Try SSL first (common for port 465)
    if port == 465:
        try:
            context = ssl.create_default_context()
            server = smtplib.SMTP_SSL(hostname, port, timeout=10, context=context)
            server.ehlo()
            return True, 'ssl', server
        except:
            pass
    
    # Try STARTTLS (common for ports 25, 587)
    try:
        server = smtplib.SMTP(hostname, port, timeout=10)
        server.ehlo()
        if server.has_extn('STARTTLS'):
            context = ssl.create_default_context()
            server.starttls(context=context)
            server.ehlo()
            return True, 'starttls', server
        else:
            # Plain connection works
            return True, 'plain', server
    except:
        pass
    
    # Try plain connection as last resort
    try:
        server = smtplib.SMTP(hostname, port, timeout=10)
        server.ehlo()
        return True, 'plain', server
    except Exception as e:
        return False, None, None


def create_test_message(sender_email, receiver_email, smtp_server, contact_email):
    """Create the test email message"""
    message = MIMEMultipart("alternative")
    message["Subject"] = f"Security Test: Open Relay Detection on {smtp_server}"
    message["From"] = sender_email
    message["To"] = receiver_email
    
    html_body = f"""
    <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .alert {{ background-color: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 20px 0; }}
                .info {{ background-color: #d1ecf1; border-left: 4px solid #17a2b8; padding: 15px; margin: 20px 0; }}
                h2 {{ color: #dc3545; }}
                code {{ background-color: #f4f4f4; padding: 2px 6px; border-radius: 3px; }}
            </style>
        </head>
        <body>
            <div class='container'>
                <h2>⚠️ Security Alert: Open Mail Relay Detected</h2>
                
                <div class='alert'>
                    <strong>If you are receiving this email, your mail server may be vulnerable to open relay attacks.</strong>
                </div>
                
                <p>This is an authorized security test to identify mail relay vulnerabilities.</p>
                
                <div class='info'>
                    <strong>Affected Server:</strong> <code>{smtp_server}</code><br>
                    <strong>Test Date:</strong> <code>{message["Date"] if "Date" in message else "N/A"}</code>
                </div>
                
                <h3>What is an Open Mail Relay?</h3>
                <p>An open mail relay allows unauthorized users to send emails through your SMTP server, 
                which can lead to:</p>
                <ul>
                    <li>Spam distribution</li>
                    <li>Phishing attacks</li>
                    <li>IP blacklisting</li>
                    <li>Reputation damage</li>
                </ul>
                
                <h3>Recommended Actions:</h3>
                <ol>
                    <li>Configure SMTP authentication requirements</li>
                    <li>Implement proper SPF and DMARC records</li>
                    <li>Restrict relay permissions to authorized users/IPs</li>
                    <li>Review and update mail server security policies</li>
                </ol>
                
                <p><strong>Please forward this email to your security team: {contact_email}</strong></p>
                
                <hr>
                <p style='font-size: 0.9em; color: #666;'>
                    This is an automated security test. If you have questions, contact: {contact_email}
                </p>
            </div>
        </body>
    </html>
    """
    
    message.attach(MIMEText(html_body, "html"))
    return message


def test_mail_relay(smtp_server, port, mode, sender_email, receiver_email, contact_email):
    """Test a single SMTP server for open relay"""
    print(f"\n{Colors.INFO}[*] Testing: {smtp_server}:{port} (mode: {mode}){Colors.ENDC}")
    
    # Test connection
    success, detected_mode, server = test_smtp_connection(smtp_server, port, mode)
    
    if not success:
        print(f"{Colors.FAIL}    [FAIL] Could not connect to {smtp_server}:{port}{Colors.ENDC}")
        return False
    
    print(f"{Colors.OK}    [INFO] Connected successfully (method: {detected_mode}){Colors.ENDC}")
    
    # Create and send test message
    try:
        message = create_test_message(sender_email, receiver_email, smtp_server, contact_email)
        server.sendmail(sender_email, receiver_email, message.as_string())
        server.quit()
        
        print(f"{Colors.WARN}    [VULNERABLE] Email sent successfully - Open relay detected!{Colors.ENDC}")
        return True
        
    except smtplib.SMTPRecipientsRefused as e:
        print(f"{Colors.OK}    [SECURE] Relay rejected (recipients refused){Colors.ENDC}")
        try:
            server.quit()
        except:
            pass
        return False
        
    except smtplib.SMTPSenderRefused as e:
        print(f"{Colors.OK}    [SECURE] Relay rejected (sender refused){Colors.ENDC}")
        try:
            server.quit()
        except:
            pass
        return False
        
    except Exception as e:
        print(f"{Colors.FAIL}    [ERROR] {str(e)}{Colors.ENDC}")
        try:
            server.quit()
        except:
            pass
        return False


def load_targets(filename):
    """Load target servers from file"""
    targets = []
    try:
        with open(filename, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    hostname, port, mode = parse_target_line(line)
                    targets.append((hostname, port, mode))
        return targets
    except FileNotFoundError:
        print(f"{Colors.FAIL}[!] Error: File '{filename}' not found{Colors.ENDC}")
        sys.exit(1)
    except Exception as e:
        print(f"{Colors.FAIL}[!] Error reading file: {e}{Colors.ENDC}")
        sys.exit(1)


def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="Test SMTP servers for open relay vulnerabilities",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Target File Format:
  One server per line in the format: hostname[:port[:mode]]
  
  Examples:
    mail.example.com                  (uses port 25, auto-detect SSL)
    mail.example.com:587              (port 587, auto-detect SSL)
    mail.example.com:465:ssl          (port 465, force SSL/TLS)
    mail.example.com:25:starttls      (port 25, force STARTTLS)
    mail.example.com:25:plain         (port 25, no encryption)
  
  Modes: auto, ssl, starttls, plain

Example Usage:
  python smtp_relay_tester.py \\
    --sender test@attacker.com \\
    --receiver admin@target.com \\
    --contact security@target.com \\
    --targets servers.txt
        """
    )
    
    parser.add_argument(
        "--sender",
        help="Email address to send from",
        dest="sender_email",
        type=str,
        required=True
    )
    
    parser.add_argument(
        "--receiver",
        help="Email address to send to",
        dest="receiver_email",
        type=str,
        required=True
    )
    
    parser.add_argument(
        "--contact",
        help="Security contact email (included in test message)",
        dest="contact_email",
        type=str,
        required=True
    )
    
    parser.add_argument(
        "--targets",
        help="File containing SMTP servers to test",
        dest="targets_file",
        type=str,
        required=True
    )
    
    return parser.parse_args()


def main():
    """Main execution function"""
    args = parse_args()
    
    print_banner()
    
    # Extract sender domain for SPF/DMARC checks
    sender_domain = args.sender_email.split('@')[1]
    
    # Check SPF and DMARC
    check_spf(sender_domain)
    check_dmarc(sender_domain)
    
    # Load targets
    print(f"\n{Colors.INFO}[*] Loading targets from {args.targets_file}...{Colors.ENDC}")
    targets = load_targets(args.targets_file)
    print(f"{Colors.OK}    [INFO] Loaded {len(targets)} target(s){Colors.ENDC}")
    
    # Test each target
    print(f"\n{Colors.BOLD}{'='*70}")
    print("Starting Open Relay Tests")
    print(f"{'='*70}{Colors.ENDC}")
    
    vulnerable_servers = []
    
    for hostname, port, mode in targets:
        if test_mail_relay(hostname, port, mode, args.sender_email, args.receiver_email, args.contact_email):
            vulnerable_servers.append(f"{hostname}:{port}")
    
    # Summary
    print(f"\n{Colors.BOLD}{'='*70}")
    print("Test Summary")
    print(f"{'='*70}{Colors.ENDC}")
    print(f"Total servers tested: {len(targets)}")
    print(f"Vulnerable servers: {len(vulnerable_servers)}")
    
    if vulnerable_servers:
        print(f"\n{Colors.WARN}[!] The following servers are vulnerable:{Colors.ENDC}")
        for server in vulnerable_servers:
            print(f"    - {server}")
    else:
        print(f"\n{Colors.OK}[✓] No open relays detected{Colors.ENDC}")
    
    print()


if __name__ == "__main__":
    main()
