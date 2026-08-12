import os
import requests
from dotenv import load_dotenv

# Load environment variables from .env
load_dotenv()

# Get VirusTotal API key
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

# VirusTotal API base URL
BASE_URL = "https://www.virustotal.com/api/v3"


def check_domain(domain):

    # Check API key
    if not VT_API_KEY:
        return {
            "success": False,
            "source": "VirusTotal",
            "error": "VIRUSTOTAL_API_KEY is not configured in .env"
        }

    # Clean domain input
    domain = (
        domain
        .replace("https://", "")
        .replace("http://", "")
        .split("/")[0]
        .strip()
    )

    # VirusTotal domain API endpoint
    url = f"{BASE_URL}/domains/{domain}"

    # API authentication
    headers = {
        "x-apikey": VT_API_KEY
    }

    try:

        # Send request to VirusTotal
        response = requests.get(
            url,
            headers=headers,
            timeout=20
        )

        # -----------------------------------------
        # Handle HTTP errors
        # -----------------------------------------

        if response.status_code == 401:
            return {
                "success": False,
                "source": "VirusTotal",
                "domain": domain,
                "error": "Invalid VirusTotal API key."
            }

        if response.status_code == 404:
            return {
                "success": False,
                "source": "VirusTotal",
                "domain": domain,
                "error": "Domain was not found in VirusTotal."
            }

        if response.status_code == 429:
            return {
                "success": False,
                "source": "VirusTotal",
                "domain": domain,
                "error": "VirusTotal API rate limit reached."
            }

        # Raise exception for other HTTP errors
        response.raise_for_status()

        # Convert response to JSON
        data = response.json()

        # -----------------------------------------
        # Extract VirusTotal attributes
        # -----------------------------------------

        attributes = data["data"]["attributes"]

        # Get analysis statistics
        analysis_stats = attributes.get(
            "last_analysis_stats",
            {}
        )

        # -----------------------------------------
        # Build clean result for AI agent
        # -----------------------------------------

        result = {
            "success": True,
            "source": "VirusTotal",
            "domain": domain,

            "reputation": attributes.get(
                "reputation"
            ),

            "malicious": analysis_stats.get(
                "malicious",
                0
            ),

            "suspicious": analysis_stats.get(
                "suspicious",
                0
            ),

            "harmless": analysis_stats.get(
                "harmless",
                0
            ),

            "undetected": analysis_stats.get(
                "undetected",
                0
            ),

            "timeout": analysis_stats.get(
                "timeout",
                0
            ),

            "categories": attributes.get(
                "categories",
                {}
            ),

            "registrar": attributes.get(
                "registrar"
            ),

            "tags": attributes.get(
                "tags",
                []
            ),

            "total_votes": attributes.get(
                "total_votes",
                {}
            )
        }

        return result

    # -----------------------------------------
    # Network timeout
    # -----------------------------------------

    except requests.exceptions.Timeout:

        return {
            "success": False,
            "source": "VirusTotal",
            "domain": domain,
            "error": "VirusTotal request timed out."
        }

    # -----------------------------------------
    # Connection / HTTP error
    # -----------------------------------------

    except requests.exceptions.RequestException as e:

        return {
            "success": False,
            "source": "VirusTotal",
            "domain": domain,
            "error": f"VirusTotal API request failed: {str(e)}"
        }

    # -----------------------------------------
    # Unexpected error
    # -----------------------------------------

    except Exception as e:

        return {
            "success": False,
            "source": "VirusTotal",
            "domain": domain,
            "error": f"Unexpected error: {str(e)}"
        }


# ------------------------------------------------
# Test the tool directly
# ------------------------------------------------

if __name__ == "__main__":

    domain = input(
        "Enter domain to check: "
    ).strip()

    result = check_domain(domain)

    print("\n========================================")
    print("       VIRUSTOTAL DOMAIN RESULT")
    print("========================================\n")

    for key, value in result.items():
        print(f"{key}: {value}")