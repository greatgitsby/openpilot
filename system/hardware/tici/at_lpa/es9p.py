import requests


def es9p_request(smdp_address: str, endpoint: str, payload: dict, error_prefix: str = "Request") -> dict:
  url = f"https://{smdp_address}/gsma/rsp2/es9plus/{endpoint}"
  headers = {"User-Agent": "gsma-rsp-lpad", "X-Admin-Protocol": "gsma/rsp/v2.2.2", "Content-Type": "application/json"}
  resp = requests.post(url, json=payload, headers=headers, timeout=30, verify=False)
  resp.raise_for_status()
  if not resp.content:
    return {}
  data = resp.json()
  if "header" in data and "functionExecutionStatus" in data["header"]:
    status = data["header"]["functionExecutionStatus"]
    if status.get("status") == "Failed":
      sd = status.get("statusCodeData", {})
      raise RuntimeError(f"{error_prefix} failed: {sd.get('reasonCode', 'unknown')}/{sd.get('subjectCode', 'unknown')} - {sd.get('message', 'unknown')}")
  return data
