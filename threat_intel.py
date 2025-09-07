import requests
import time

# Query the NVD API for CVEs related to a vendor/product (optionally filter by version).
def get_nvd_cves(product, version=None, vendor=None, max_results=5):
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "keywordSearch": product,
        "resultsPerPage": max_results
    }
    if version:
        params["keywordSearch"] += f" {version}"
    if vendor:
        params["keywordSearch"] += f" {vendor}"
    try:
        resp = requests.get(base_url, params=params, timeout=15)
        if resp.status_code == 200:
            cves = resp.json().get("vulnerabilities", [])
            results = []
            for cve in cves:
                cve_id = cve["cve"]["id"]
                desc = cve["cve"]["descriptions"][0]["value"]
                refs = [ref["url"] for ref in cve["cve"].get("references", [])]
                results.append({"id": cve_id, "summary": desc, "references": refs})
            return results
        else:
            print("NVD API error:", resp.status_code)
            return []
    except Exception as e:
        print("NVD API exception:", e)
        return []

