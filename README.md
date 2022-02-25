### Summary

**autoSSRF** is your best ally for identifying SSRF vulnerabilities at scale. Different from other ssrf automation tools, **autoSSRF** comes with the two following original features :

- **Smart fuzzing on relevant SSRF GET parameters**
    
    When fuzzing, **autoSSRF** only focuses on the common parameters related to SSRF (`?url=`, `?uri=`, ..) and doesn’t interfere with everything else. This ensures that the original URL is still correctly understood by the tested web-application, something that might doesn’t happen with a tool blindly spraying every query parameters.
    
- **Context-based dynamic payloads generation**
    
    For the given URL : `[https://host.com/?fileURL=https://authorizedhost.com](https://host.com/?fileURL=https://whitelistedhost.comn)`, **autoSSRF** would recognize *authorizedhost.com* as the potentially white-listed host for the web-application, and generate payloads dynamically based on that, attempting to bypass the white-list validation. 
    It would result to interesting payloads such as : `http://authorizedhost.attacker.com`, `http://authorizedhost%252F@attacker.com`, etc.
    

Furthermore, this tool guarantees almost no **false-positives**. The detection relies on the great ProjectDiscovery’s *[interactsh](https://github.com/projectdiscovery/interactsh)*, allowing **autoSSRF** to confidently identify out-of-band DNS/HTTP interactions.

---

### Usage

```bash
python3 autossrf.py -h
```

This displays help for the tool.

```bash
usage: autossrf.py [-h] [--file FILE] [--url URL] [--output] [--verbose]

options:
  -h, --help            show this help  message and exit
  --file FILE, -f FILE  file of all URLs to be tested against SSRF
  --url URL, -u URL     url to be tested against SSRF
  --output, -o          output file path
  --verbose, -v         activate verbose mode
```

Single URL target: 

```bash
python3 autossrf.py -u https://www.host.com/?param1=X&param2=Y&param2=Z
```

Multiple URLs target with verbose: 

```bash
python3 autossrf.py -f urls.txt -v
```

---

### Installation

1 - Clone 

```bash
git clone https://github.com/Th0h0/autossrf.git
```

2  - Install requirements

```bash
cd autossrf 
pip install -r requirements.txt
```

---

### License

**autoSSRF** is distributed under [MIT License](https://github.com/Th0h0/autossrf/blob/master/LICENSE.md).
