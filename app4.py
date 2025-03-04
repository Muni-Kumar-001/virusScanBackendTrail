from flask import Flask, request, jsonify
import requests
import time

app = Flask(__name__)

# VirusTotal API Configuration
VT_URL = "https://www.virustotal.com/api/v3/urls"
API_KEY = "b46926f30be77461ad70102829fc0b4b03c04ed3af493f4140db433b2a599e9b"
HEADERS = {
    "x-apikey": API_KEY,
    "accept": "application/json",
    "content-type": "application/x-www-form-urlencoded"
}

@app.route("/scan", methods=["POST"])
def scan_url():
    """API endpoint to scan a URL using VirusTotal."""
    try:
        data = request.get_json()
        url_to_scan = data.get("url")

        if not url_to_scan:
            return jsonify({"error": "URL is required"}), 400

        # Submit URL to VirusTotal
        response = requests.post(VT_URL, headers=HEADERS, data={"url": url_to_scan})
        
        if response.status_code != 200:
            return jsonify({"error": "Failed to submit URL"}), 500

        result = response.json()
        analysis_id = result["data"]["id"]

        # Wait 5 seconds for VirusTotal to process
        time.sleep(5)

        # Retrieve the scan report
        report_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        report_response = requests.get(report_url, headers=HEADERS)

        if report_response.status_code != 200:
            return jsonify({"error": "Failed to retrieve report"}), 500

        report = report_response.json()
        stats = report["data"]["attributes"]["stats"]

        # Determine if the URL is safe or malicious
        status = "Spam" if stats["malicious"] > 0 else "Ham"

        return jsonify({"status": status})

    except requests.RequestException as e:
        return jsonify({"error": "Request failed"}), 500

if __name__ == "__main__":
    app.run(debug=True)
