import warnings
warnings.filterwarnings("ignore")
from Wappalyzer import Wappalyzer, WebPage
import threat_intel
import json

#	Extracts a list of (vendor, product, version) tuples from Wappalyzer output.
def extract_tech_versions(tech_info):
	techs = []
	for tech, details in tech_info.items():
		# Try to get version if available
		version = None
		if details.get('versions') and details['versions']:
			version = details['versions'][0]
		vendor = tech.lower().split()[0]
		product = tech.lower().replace(' ', '_')
		techs.append((vendor, product, version))
	return techs

def main():
	url = 'http://testphp.vulnweb.com/login.php' 
	wappalyzer = Wappalyzer.latest()
	webpage = WebPage.new_from_url(url)
	tech_info = wappalyzer.analyze_with_versions_and_categories(webpage)
	print("\n🔎 Detected tech stack:")
	print(json.dumps(tech_info, indent=2))

	techs = extract_tech_versions(tech_info)
	all_vulns = {}
	for vendor, product, version in techs:
		vulns = threat_intel.get_nvd_cves(vendor, product, version)
		all_vulns[f"{vendor}/{product} {version or ''}".strip()] = vulns

	print("\n\U0001F4C8 Vulnerabilities mapped to tech stack:")
	print(json.dumps(all_vulns, indent=2))

if __name__ == "__main__":
	main()


