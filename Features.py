from datetime import datetime 
import urllib.request
from bs4 import BeautifulSoup
import google
import time
import re
import whois
from urllib.parse import urlparse,urlencode
import socket
import numpy as np
import pandas as pd
from urllib.error import HTTPError

class Hello:
    def __init__(self):
        pass
    
    def getProtocol(self,url):
        return urlparse(url).scheme
    
    def getDomain(self,url):
        return urlparse(url).netloc

    def getPath(self,url):
        return urlparse(url).path
        
    
    def url_length(self,url):
        if len(url)<54:
            return 0
        elif len(url)>=54 and len(url)<=75:
            return 2
        else:
            return 1
    
    def check_at(self,url):
        if '@' in url:
            return 1
        else:
            return 0
    
    def redirection(self,url):
        if '//' in urlparse(url).path:
            return 1
        else:
            return 0
     
    
    def check_dash(self,url):
        if '-' in urlparse(url).netloc:
            return 1
        else:
            return 0
    
    def check_dots(self,url):
        if url.count('.') < 3:
            return 0
        elif url.count('.') == 3:
            return 2
        else:
            return 1
    
    def having_ip_address(self,url):
        match=re.search('(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  #IPv4
                    '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)'  #IPv4 in hexadecimal
                    '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}',url)     #Ipv6
        if match:
            #print match.group()
            return 1
        else:
            #print 'No matching pattern found'
            return 0
    
    
    def shortening_service(self,url):
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
    
    
    def https_token(self,url):
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
    

        
    
    def web_traffic(self,url):
        try:
            rank = BeautifulSoup(urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + url).read(), "xml").find("REACH")['RANK']
        except TypeError:
            return 1
        except HTTPError:
            return 2
        rank= int(rank)
        if (rank<100000):
            return 0
        else:
            return 2
            
    
    
        
    def check_date(self,url):
        dns=0
        try:
            domain_name=whois.whois(urlparse(url).netloc)
        except:
            dns=1
        if dns==1:
            return 1
        else:
            expiry=domain_name.expiration_date
            today=time.strftime("%Y-%m-%d")
            today=datetime.strptime(today,"%Y-%m-%d")
            if expiry is None:
                return 1
            elif type(expiry) is list or type(today) is list:
                return 2
            else:
                creation_date = domain_name.creation_date
                expiration_date = domain_name.expiration_date
                if (isinstance(creation_date,str) or isinstance(expiration_date,str)):
                    try:
                        creation_date = datetime.strptime(creation_date,'%Y-%m-%d')
                        expiration_date = datetime.strptime(expiration_date,"%Y-%m-%d")
                    except:
                        return 2
                registration_time=abs((expiration_date-today).days)
                if (registration_time/365)<=1:
                    return 1
                else:
                    return 0
    
       
    def check_age(self,url):
        dns=0
        try:
            domain_name=whois.whois(urlparse(url).netloc)
        except:
            dns=1
        if dns==1:
            return 1
        else:
            creation=domain_name.creation_date
            expiry=domain_name.expiration_date
            if (isinstance(creation,str) or isinstance(expiry,str)):
                try:
                    creation = datetime.strptime(creation,'%Y-%m-%d')
                    expiry = datetime.strptime(expiry,"%Y-%m-%d")
                except:
                    return 2
            
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
                
        
        
    def check_dns(self,url):
        dns=0
        try:
            domain_name=whois.whois(urlparse(url).netloc)
            #print(domain_name)
        except:
            dns=1
        if dns==1:
            return 1
        else:
            return 0

#PhishTank  and Stopbadware
#Top Phishing IPs or Top Phishing Domains->Malicious
    def statistical_report(self,url):
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





    