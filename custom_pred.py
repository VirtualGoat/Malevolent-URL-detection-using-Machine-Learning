
from Features import Hello
import numpy as np
import pandas as pd
import pickle




# =============================================================================
# You can paste your own URLs to predict or you can use the dataset data.csv
# =============================================================================

arr=np.array(['https://www.google.com/'])

#https://www.phishtank.com/
# =============================================================================
# x=arr['url'][:50]
# =============================================================================

#arr=pd.read_csv('dataset/his.csv')
#arr=arr['url']
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
for url in arr:
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

    
d={'Having_IP':pd.Series(having_ip),'URL_length':pd.Series(len_url),'@':pd.Series(having_at_symbol),
   'Redirection':pd.Series(redirection_symbol),'Prefix_Suffix_separation':pd.Series(prefix_suffix_separation),
    'SubDomains':pd.Series(sub_domains),'tiny_url':pd.Series(tiny_url),
    'Web traffic':pd.Series(web_traffic),
    'Domain_length':pd.Series(domain_registration_length),'DNS record':pd.Series(dns_record),
    'statistical_report':pd.Series(statistical_report),'Domain Age':pd.Series(age_domain),
    'HTTP token':pd.Series(http_tokens)}

finaldata=pd.DataFrame(d)


abc=finaldata.iloc[:,:].values

file= 'RandomForest.pkl'
with open(file,'rb') as f:
    classifier=pickle.load(f)
f.close()

x_pred=classifier.predict(abc)


print(x_pred)
