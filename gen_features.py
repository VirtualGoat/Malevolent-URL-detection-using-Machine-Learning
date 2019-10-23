
from Features import Hello
import pandas as pd
import numpy as np
from cython.parallel import prange




df=pd.read_csv("dataset/good_urls.txt",names=["url"])
#df=pd.read_csv("dataset/bad_urls.txt",names=["url"])
for i in prange(0,10000):
    pass

protocol = []
domain = []
path = []
having_ip = []
len_url = []
having_at_symbol = []
redirection_symbol = []
prefix_suffix_separation = []
sub_domains = []
tiny_url = []
abnormal_url = []
web_traffic = []
domain_registration_length = []
dns_record = []
statistical_report = []
age_domain = []
http_tokens = []

a=Hello()
n=len(df['url'])

for i in range(n):
    url=df['url'][i]
    print(i)
    print(url)
    protocol.append(a.getProtocol(url))
    path.append(a.getPath(url))
    having_ip.append(a.having_ip_address(url))
    domain.append(a.getDomain(url))
    len_url.append(a.url_length(url))
    having_at_symbol.append(a.check_at(url))
    redirection_symbol.append(a.redirection(url))
    prefix_suffix_separation.append(a.check_dash(url))
    sub_domains.append(a.check_dots(url))
    tiny_url.append(a.shortening_service(url))
    web_traffic.append(a.web_traffic(url))
    domain_registration_length.append(a.check_date(url))
    dns_record.append(a.check_dns(url))
    statistical_report.append(a.statistical_report(url))
    age_domain.append(a.check_age(url))
    http_tokens.append(a.https_token(url))
    



label=[]
for i in range(989):
    label.append(0)
#    label.append(1)    


    
d={'Protocol':pd.Series(protocol),'Domain':pd.Series(domain),'Path':pd.Series(path),
   'Having_IP':pd.Series(having_ip),'URL_length':pd.Series(len_url),'@':pd.Series(having_at_symbol),
   'Redirection':pd.Series(redirection_symbol),'Prefix_Suffix_separation':pd.Series(prefix_suffix_separation),
    'SubDomains':pd.Series(sub_domains),'tiny_url':pd.Series(tiny_url),
    'Web traffic':pd.Series(web_traffic),
    'Domain_length':pd.Series(domain_registration_length),'DNS record':pd.Series(dns_record),
    'statistical_report':pd.Series(statistical_report),'Domain Age':pd.Series(age_domain),
    'HTTP token':pd.Series(http_tokens),   
    'label':pd.Series(label)}

finaldata=pd.DataFrame(d)
#finaldata.to_csv("generated_features/bad-urls.csv",index=False,encoding='UTF-8')
finaldata.to_csv("generated_features/good1-urls.csv",index=False,encoding='UTF-8')






