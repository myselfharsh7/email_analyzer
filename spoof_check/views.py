from django.shortcuts import render
import dns.resolver

def get_txt_record(domain, prefix=""):
    """Fetch TXT records for the given domain."""
    try:
        query_domain = f"{prefix}.{domain}" if prefix else domain
        answers = dns.resolver.resolve(query_domain, "TXT")
        return [b"".join(txt.strings).decode() for txt in answers]
    except Exception as e:
        return [f"Error: {e}"]

def check_records(domain):
    records = {
        'domain': domain,
        'spf': False,
        'spf_details': '',
        'spf_all_present': False,
        'dmarc': False,
        'dmarc_details': '',
        'dmarc_enforced': False,
        'spoofable': True
    }

    # Check SPF
    spf_records = get_txt_record(domain)
    if spf_records and not spf_records[0].startswith("Error"):
        records['spf'] = True
        records['spf_details'] = "; ".join(spf_records)
        records['spf_all_present'] = any("~all" in r or "-all" in r for r in spf_records)

    # Check DMARC
    dmarc_records = get_txt_record(domain, "_dmarc")
    if dmarc_records and not dmarc_records[0].startswith("Error"):
        records['dmarc'] = True
        records['dmarc_details'] = "; ".join(dmarc_records)
        records['dmarc_enforced'] = any("p=reject" in r for r in dmarc_records)

    # Determine spoofability
    if records['spf'] and records['dmarc'] and records['spf_all_present'] and records['dmarc_enforced']:
        records['spoofable'] = False

    return records


def spoof_check(request):
    records = None
    if request.method == 'POST':
        domain = request.POST.get('host')
        records = check_records(domain)
    return render(request, 'spoof_check.html', {'records': records})
