"""
Created on Mon Aug 12 21:26:24 2019

@author: Parth
"""
from datetime import datetime 
import urllib.request
from bs4 import BeautifulSoup
import google
import time
import re
import whois
import socket
import numpy as np
import pandas as pd
from cython.parallel import prange
itime = datetime.now()
for i in prange(0,10000):
    pass
ftime = datetime.now()
print(ftime-itime)


df=pd.read_csv("100-legitimate-art.txt")
sep_protocol=df['websites'].str.split("://",expand=True)
get_domain=sep_protocol[1].str.split("/",1,expand=True)
get_domain.columns=["domain",'path']
protocol_dname_path=pd.concat([sep_protocol[0],get_domain],axis=1)
protocol_dname_path.columns=['protocol','domain','path']


#Used to classify the URL based on its length
def url_length(url):
    if len(url)<54:
        return 0
    elif len(url)>=54 and len(url)<=75:
        return 2
    else:
        return 1

protocol_dname_path['url_length']=df['websites'].apply(url_length)

def check_at(url):
    if 'a' in url:
        return 1
    else:
        return 0
    
protocol_dname_path['check_at']=df['websites'].apply(check_at)

def redirection(url):
    if '//' in url:
        return 1
    else:
         return 0
    
protocol_dname_path['redirection']=sep_protocol[1].apply(redirection)
    

def check_dash(url):
    if '-' in url:
        return 1
    else:
        return 0
protocol_dname_path['dash']=sep_protocol[1].apply(check_dash)

def check_dots(url):
    if url.count('.') < 3:
        return 0
    elif url.count('.') == 3:
        return 2
    else:
        return 1
protocol_dname_path['check_dots']=get_domain['domain'].apply(check_dots)


def having_ip_address(url):
    match=re.search('(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  #IPv4
                    '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)'  #IPv4 in hexadecimal
                    '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}',url)     #Ipv6
    if match:
        #print match.group()
        return 1
    else:
        #print 'No matching pattern found'
        return 0

protocol_dname_path['having_ip_address']=df['websites'].apply(having_ip_address)


def shortening_service(url):
    match=re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                    'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                    'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                    'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                    'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                    'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                    'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net',url)
    if match:
        return 1
    else:
        return 0
    
    
protocol_dname_path['shortening_service']=df['websites'].apply(shortening_service)

def https_token(url):
    match=re.search('https://|http://',url)
    try:
        if match.start(0)==0 and match.start(0) is not None:
            url=url[match.end(0):]
            match=re.search('http|https',url)
            if match:
                return 1
            else:
                return 0
    except:
        return 1
    
protocol_dname_path['https_token']=df['websites'].apply(https_token)


def abnormal_url_mini(domain,url):
    host=domain.domain
    match=re.search(host,url)
    if match:
        return 0
    else:
        return 1

def abnormal_url_big(url):
    dns=0
    domain=url.split("://")
    fdomain=domain[1].split("/",1)
    try:
        domain_name=whois.whois(fdomain[0])
        
    except:
        dns=1
    if dns==1:
        return 1
    else:
        return abnormal_url_mini(domain_name,url)
       
protocol_dname_path['abnormal_url']=df['websites'].apply(abnormal_url_big)



def web_traffic(url):
    try:
        rank = BeautifulSoup(urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + url).read(), "xml").find("REACH")['RANK']
    except TypeError:
        return 1
    rank= int(rank)
    if (rank<100000):
        return 0
    else:
        return 2
    
protocol_dname_path['web_traffic']=df['websites'].apply(web_traffic)


def check_date_mini(domain):
    expiry=domain.expiration_date
    today=time.strftime("%Y-%m-%d")
    today=datetime.strptime(today,"%Y-%m-%d")
    if expiry is None:
        return 1
    elif type(expiry) is list or type(today) is list:
        return 2
    else:
        registration_time=abs((expiry-today).days)
        if (registration_time/365)<=1:
            return 1
        else:
            return 0
    
    
    
def check_date_main(domain):
    dns=0
    try:
        domain_name=whois.whois(domain)
    except:
        dns=1
    if dns==1:
        return 1
    else:
        return check_date_mini(domain_name)
    
protocol_dname_path['check_date']=get_domain['domain'].apply(check_date_main)
    
def check_age_mini(domain):
    creation=domain.creation_date
    expiry=domain.expiration_date
    
    if ((expiry is None) or (creation is None)):
        return 1
    elif type(expiry) is list or type(creation) is list:
        return 2
    else:
        age=abs((expiry-creation).days)
        if (age/30)<6:
            return 1
        else:
            return 0
    
    
    
def check_age_main(domain):
    dns=0
    try:
        domain_name=whois.whois(domain)
    except:
        dns=1
    if dns==1:
        return 1
    else:
        return check_date_mini(domain_name)

protocol_dname_path['check_age']=get_domain['domain'].apply(check_age_main)

def check_dns(domain):
    dns=0
    try:
        domain_name=whois.whois(domain)
        print(domain)
    except:
        dns=1
    if dns==1:
        return 1
    else:
        return dns

protocol_dname_path['check_dns']=get_domain['domain'].apply(check_dns)


def statistical_report(url):
    hostname = url
    h = [(x.start(0), x.end(0)) for x in re.finditer('https://|http://|www.|https://www.|http://www.', hostname)]
    z = int(len(h))
    if z != 0:
        y = h[0][1]
        hostname = hostname[y:]
        h = [(x.start(0), x.end(0)) for x in re.finditer('/', hostname)]
        z = int(len(h))
        if z != 0:
            hostname = hostname[:h[0][0]]
    url_match=re.search('at\.ua|usa\.cc|baltazarpresentes\.com\.br|pe\.hu|esy\.es|hol\.es|sweddy\.com|myjino\.ru|96\.lt|ow\.ly',url)
    try:
        ip_address = socket.gethostbyname(hostname)
        ip_match=re.search('146\.112\.61\.108|213\.174\.157\.151|121\.50\.168\.88|192\.185\.217\.116|78\.46\.211\.158|181\.174\.165\.13|46\.242\.145\.103|121\.50\.168\.40|83\.125\.22\.219|46\.242\.145\.98|107\.151\.148\.44|107\.151\.148\.107|64\.70\.19\.203|199\.184\.144\.27|107\.151\.148\.108|107\.151\.148\.109|119\.28\.52\.61|54\.83\.43\.69|52\.69\.166\.231|216\.58\.192\.225|118\.184\.25\.86|67\.208\.74\.71|23\.253\.126\.58|104\.239\.157\.210|175\.126\.123\.219|141\.8\.224\.221|10\.10\.10\.10|43\.229\.108\.32|103\.232\.215\.140|69\.172\.201\.153|216\.218\.185\.162|54\.225\.104\.146|103\.243\.24\.98|199\.59\.243\.120|31\.170\.160\.61|213\.19\.128\.77|62\.113\.226\.131|208\.100\.26\.234|195\.16\.127\.102|195\.16\.127\.157|34\.196\.13\.28|103\.224\.212\.222|172\.217\.4\.225|54\.72\.9\.51|192\.64\.147\.141|198\.200\.56\.183|23\.253\.164\.103|52\.48\.191\.26|52\.214\.197\.72|87\.98\.255\.18|209\.99\.17\.27|216\.38\.62\.18|104\.130\.124\.96|47\.89\.58\.141|78\.46\.211\.158|54\.86\.225\.156|54\.82\.156\.19|37\.157\.192\.102|204\.11\.56\.48|110\.34\.231\.42',ip_address)  
    except:
        return 1

    if url_match:
        return 1
    else:
        return 0
    
protocol_dname_path['stats']=df['websites'].apply(statistical_report)

