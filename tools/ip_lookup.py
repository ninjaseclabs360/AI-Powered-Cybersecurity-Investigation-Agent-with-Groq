import socket


def resolve_domain(domain):

    try:
        ip = socket.gethostbyname(domain)

        return {
            "domain": domain,
            "ip": ip,
            "status": "success"
        }

    except Exception as e:

        return {
            "domain": domain,
            "status": "failed",
            "error": str(e)
        }