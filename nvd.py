def get_data_from_NVD():
    ready_to_send = []
    # This function gets the CVEs published in NVD database in the last 24 hours
    # Get the current date and time
    current_datetime = datetime.now()
    
    # Get the date and time 24 hours ago
    yesterday_datetime = current_datetime - timedelta(hours=24)
    
    # Format the dates as strings in the desired format
    current_date = current_datetime.strftime('%Y-%m-%dT%H:%M:%S')
    yesterday_date = yesterday_datetime.strftime('%Y-%m-%dT%H:%M:%S')
    
    
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0/?pubStartDate={1}%2B01:00&pubEndDate={0}%2B01:00".format(current_date, yesterday_date)
    response = requests.get(url)
    response_json = response.json()
    
    lastCVEs = response_json["vulnerabilities"]

    for cve in lastCVEs:
        entry = {}
        
        # CVE
        entry["cve"] = cve["cve"]["id"]

        # Status
        entry["status"] = cve["cve"]["vulnStatus"]
        descriptions = cve["cve"]["descriptions"]
        for description in descriptions:
            if description["lang"] == "en":
                entry["description"] = description["value"]
                break

        # Metrics
        if "cvssMetricV31" in cve["cve"]["metrics"]:
            entry["metrics"] = {"baseScore":cve["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"]["baseScore"],
                            "baseSeverity":cve["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"]["baseSeverity"],
                            "exploitabilityScore":cve["cve"]["metrics"]["cvssMetricV31"][0]["exploitabilityScore"],
                            "impactScore":cve["cve"]["metrics"]["cvssMetricV31"][0]["impactScore"]}
        else:
            entry["metrics"] = {}

        # CPE
        if "configurations" in cve["cve"]:
            configs = cve["cve"]["configurations"]
        else: 
            configs = ""

        entry["cpe"] = []

        for config in configs:
            nodes = config["nodes"]
            for node in nodes:
                matches = node["cpeMatch"]
                for match in matches: 
                    cpe = match["criteria"]
                    part = cpe.split(":")[2]
                    vendor = cpe.split(":")[3]
                    product = cpe.split(":")[4]

                    if "versionStartIncluding" in match:
                        versionStartIncluding = match["versionStartIncluding"]
                    else:
                        versionStartIncluding = ""
                    
                    if "versionEndExcluding" in match:
                       versionEndExcluding = match["versionEndExcluding"]
                    else:
                        versionEndExcluding = ""

                    new_entry = {} 
                    new_entry["part"] = part
                    new_entry["vendor"] = vendor
                    new_entry["product"] = product
                    new_entry["versionStartIncluding"] = versionStartIncluding
                    new_entry["versionEndExcluding"] = versionEndExcluding

                    entry["cpe"].append(new_entry)

        if len(entry["cpe"]) == 0:
            # do whatever
            pass
        else:
            ready_to_send.append(entry)
         
    return ready_to_send
