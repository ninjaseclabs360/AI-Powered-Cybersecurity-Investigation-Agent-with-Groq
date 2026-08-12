import os
import json

from dotenv import load_dotenv
from groq import Groq

from tools.virustotal import check_domain


load_dotenv()


client = Groq(
    api_key=os.getenv("GROQ_API_KEY")
)

SYSTEM_PROMPT = """
You are a cybersecurity investigation AI agent.

You analyse evidence obtained from security tools such as
VirusTotal, DNS, HTTP, WHOIS, and threat intelligence platforms.

IMPORTANT RULES:

1. Never invent technical findings.

2. Only make claims supported by the evidence provided by the tools.

3. Clearly distinguish:
   - FACT
   - OBSERVATION
   - ASSESSMENT
   - RECOMMENDATION

4. VirusTotal reputation is a reputation score. Do not describe
   it as a percentage, confidence score, or proof that a domain
   is safe.

5. VirusTotal categories are vendor classifications. Do not
   assume that a category represents the actual primary purpose
   of the domain.

6. If malicious detections are 0, say:
   "No malicious detections were reported by the VirusTotal
   engines included in this result."

   Do NOT say:
   "The domain is safe."

7. If suspicious detections are 0, report that as an observation,
   not proof of safety.

8. Do not claim SQL injection, XSS, RCE, outdated software,
   malware, phishing, or other vulnerabilities unless there is
   actual evidence.

9. Do not infer security problems from website appearance,
   popularity, Alexa ranking, number of pages, or design.

10. If information is unavailable, say "Not available".

11. Do not confuse VirusTotal vendor categories with confirmed
    security findings.

12. Keep the analysis evidence-based and suitable for a SOC analyst.
"""

def analyse_with_groq(domain, vt_result):

    prompt = f"""
Investigate the following domain:

Domain:
{domain}

VirusTotal evidence:

{json.dumps(vt_result, indent=2)}

Analyse the evidence and provide:

1. Domain
2. VirusTotal reputation
3. Malicious detections
4. Suspicious detections
5. Harmless detections
6. Categories
7. Security assessment
8. Recommended next steps

Do not invent information that is not contained in the evidence.
"""

    response = client.chat.completions.create(

        model="llama-3.3-70b-versatile",

        messages=[
            {
                "role": "system",
                "content": SYSTEM_PROMPT
            },
            {
                "role": "user",
                "content": prompt
            }
        ],

        temperature=0.1
    )

    return response.choices[0].message.content


def main():

    while True:

        domain = input("\nYou: ")

        if domain.lower() in ["exit", "quit"]:
            break

        print("\n[+] Querying VirusTotal...")

        vt_result = check_domain(domain)

        if not vt_result.get("success"):

            print("\n[!] VirusTotal Error:")
            print(vt_result.get("error"))

            continue

        print("[+] VirusTotal data received")

        print("\n[+] Sending evidence to Groq...")

        analysis = analyse_with_groq(
            domain,
            vt_result
        )

        print("\nAgent:")
        print(analysis)


if __name__ == "__main__":
    main()