from tools.virustotal import check_domain


domain = input("Enter domain: ")

result = check_domain(domain)

print("\nVirusTotal Result:")
print(result)