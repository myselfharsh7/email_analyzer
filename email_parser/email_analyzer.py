import email
from email import policy
from email.parser import BytesParser
import re
import virustotal_python # type: ignore
from base64 import urlsafe_b64encode
import hashlib
import dns.resolver # type: ignore
import requests # type: ignore

def read_eml_file(file_content):
    msg = BytesParser(policy=policy.default).parsebytes(file_content)
    #print(msg)
    return msg

def extract_email_info(msg):
    received_headers = msg.get('Received', '')
    # Extract all IPs and get their geolocation
    ip_addresses = extract_ips_from_headers(msg)
    ip_geolocations = [get_geolocation(ip) for ip in ip_addresses]

    email_info = {
        "from": msg.get('From', ''),
        "to": msg.get('To', ''),
        "x-originating-ip": msg.get('X-Originating-IP', ''),
        "message-id": msg.get('Message-ID', ''),
        "spf-record": msg.get('Authentication-Results', '').lower().find('spf=pass') != -1,
        "dmarc-record": msg.get('Authentication-Results', '').lower().find('dmarc=pass') != -1,
        "spoofed": msg.get('Authentication-Results', '').lower().find('spf=fail') != -1,
        "ip-address": received_headers,
        "sender-client": msg.get('X-Mailer', ''),
        "spoofed-mail": msg.get('Authentication-Results', '').lower().find('spf=softfail') != -1,
        "dt": msg.get('Date', ''),
        "content-type": msg.get_content_type(),
        "subject": msg.get('Subject', ''),
        "return-path": msg.get('Return-Path', ''),
        "mx_records": get_mx_records(msg.get('From', '')),
       "origin_server": extract_origin_server(msg),
        "spf_status": "softfail" if "spf=softfail" in msg.get('Authentication-Results', '').lower() else "pass",
        "ip-geolocation":  ip_geolocations
    }
    return email_info


def extract_origin_server(msg):
    received_headers = msg.get_all('Received', [])
    if not received_headers:
        return "Unknown"
    
    first_received = received_headers[1]  
    return first_received  # Return full header for debugging

#ip info about header
def extract_ips_from_headers(msg):
    """Extracts all IPs from the 'Received' headers of an email."""
    received_headers = msg.get_all('Received', [])
    all_ips = []
    
    for header in received_headers:
        found_ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', header)
        all_ips.extend(found_ips)

    return list(set(all_ips))  # Remove duplicates


def get_geolocation(ip):
    """Fetches geolocation data for a given IP."""
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}")
        geo_data = response.json()
        
        if geo_data['status'] == 'success':
            return {
                "IP": ip,
                "Country": geo_data['country'],
                "Region": geo_data['regionName'],
                "City": geo_data['city'],
                "ISP": geo_data['isp'],
                "Latitude": geo_data['lat'],
                "Longitude": geo_data['lon']
            }
    except Exception as e:
        return {"IP": ip, "Error": str(e)}
    
    return {"IP": ip, "Error": "Failed to fetch geolocation"}


def get_mx_records(email_address):
    domain = email_address.split('@')[-1]
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        return [{"exchange": record.exchange.to_text(), "preference": record.preference} for record in mx_records]
    except dns.resolver.NoAnswer:
        return []
    except dns.resolver.NXDOMAIN:
        return []
    except Exception as e:
        return [{"error": str(e)}]

def extract_message_body(msg):
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type == 'text/plain' or content_type == 'text/html':
                return part.get_payload(decode=True).decode('utf-8', 'ignore')
    else:
        return msg.get_payload(decode=True).decode('utf-8', 'ignore')

def has_attachment(part):
    content_disposition = part.get("Content-Disposition", "")
    return content_disposition.startswith("attachment")

def check_attachments(msg):
    attachments = []
    if msg.is_multipart():
        for part in msg.walk():
            if has_attachment(part):
                filename = part.get_filename()
                if filename:
                    attachments.append((filename, part))
    return attachments

def extract_urls(text):
    url_pattern = re.compile(
        r'(?i)\b((?:(?:https?://|ftp://|www\d{0,3}[.])?[a-z0-9.-]+\.[a-z]{2,4}(?:/[^\s()<>]*)?))'
    )
    urls = re.findall(url_pattern, text)
    return urls

def check_for_urls(msg):
    email_body = extract_message_body(msg)
    urls = extract_urls(email_body)
    return urls
#0fba6765b071f5b9f1dedba636b06e6f8a1c31b5bd40f5938d673dce394bbd20
#bbcb8af1c775f8b36538ad5adec51774a681167be81b4352108fdd4ff5b19986
def url_scan(url):
    with virustotal_python.Virustotal("0fba6765b071f5b9f1dedba636b06e6f8a1c31b5bd40f5938d673dce394bbd20") as vtotal:
        try:
            resp = vtotal.request("urls", data={"url": url}, method="POST")
            if resp.status_code == 200:
                #print(resp.json())
                url_id = urlsafe_b64encode(url.encode()).decode().strip("=")
                report = vtotal.request(f"urls/{url_id}")
                reputation = report.data['attributes']['reputation']
                harmless = report.data['attributes']['last_analysis_stats']['harmless']
                malicious = report.data['attributes']['last_analysis_stats']['malicious']
                suspicious = report.data['attributes']['last_analysis_stats']['suspicious']
                sus = int(malicious) + int(suspicious)
                vendor_flags = []
            if 'last_analysis_results' in report.data['attributes']:
                for vendor, details in report.data['attributes']['last_analysis_results'].items():
                    if details['category'] == 'malicious':
                        vendor_flags.append({
                            "vendor": vendor,
                            "malware_type": details['result']
                        })
                        print(report.data)
                        print ("/////////////////////////////////////\n")
                        print(vendor_flags)

                return {
                    "url": url,
                    "reputation": reputation,
                    "harmless": harmless,
                    "malicious": sus,
                    "flagged_by": vendor_flags
                }
            elif resp.status_code == 404:
                return {"url": url, "error": "Page not found"}
            else:
                return {"url": url, "error": f"Error: {resp.status_code} - {resp.text}"}
        except virustotal_python.VirustotalError as err:
            return {"url": url, "error": f"Failed to send URL: {url} for analysis and get the report: {err}"}
        
def get_file_hashes(file_content):
    md5_hash = hashlib.md5()

    if isinstance(file_content, str):
        file_content = file_content.encode()  # Convert string to bytes
    elif file_content is None:
        file_content = b""  # Use empty bytes if None

    md5_hash.update(file_content)
    return md5_hash.hexdigest()


def attachment_scan(md5_hash):
    with virustotal_python.Virustotal("0fba6765b071f5b9f1dedba636b06e6f8a1c31b5bd40f5938d673dce394bbd20") as vtotal:
        try:
            report = vtotal.request(f"files/{md5_hash}")
            harmless = report.data['attributes']['last_analysis_stats']['harmless']
            malicious = report.data['attributes']['last_analysis_stats']['malicious']
            suspicious = report.data['attributes']['last_analysis_stats']['suspicious']
            sus = int(malicious) + int(suspicious)

            # Extract security vendors and malware types
            vendor_flags = []
            if 'last_analysis_results' in report.data['attributes']:
                for vendor, details in report.data['attributes']['last_analysis_results'].items():
                    if details['category'] == 'malicious':
                        vendor_flags.append({
                            "vendor": vendor,
                            "malware_type": details['result']
                        })
            print(vendor_flags)
            return {
                "md5": md5_hash,
                "harmless": harmless,
                "malicious": sus,
                "flagged_by": vendor_flags
            }
        except virustotal_python.VirustotalError as err:
            return {"md5": md5_hash, "error": f"Failed to get report for hash: {md5_hash} - {err}"}

def analyze_email(file):
    file_content = file.read()
    msg = read_eml_file(file_content)
    email_info = extract_email_info(msg)
    urls = check_for_urls(msg)
    url_scans = [url_scan(url) for url in urls]
    attachments = check_attachments(msg)
    attachment_scans = []
    for filename, part in attachments:
        attachment_content = part.get_payload(decode=True)
        md5_hash = get_file_hashes(attachment_content)
        scan_result = attachment_scan(md5_hash)
        attachment_scans.append({
            "filename": filename,
            "scan_result": scan_result
        })
    return {
        "email_info": email_info,
        "url_scans": url_scans,
        "attachment_scans": attachment_scans
    }
