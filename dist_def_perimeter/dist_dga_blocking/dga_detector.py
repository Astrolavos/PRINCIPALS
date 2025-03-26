# source: https://github.com/philarkwright/DGA-Detection

from scapy.all import *
import tldextract
import json
import scipy
from dga_data_sender import db_post

def process_traffic(pkt):
    if IP in pkt:
        if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0:
            domain_name = pkt.getlayer(DNS).qd.qname.decode()
            input_domain = tldextract.extract(domain_name).domain
            if check_domain(input_domain):
                print("DGA FOUND",input_domain)
                db_post(input_domain)
            else:
                print("NON DGA",input_domain)
    

def capture_traffic(interface_name):
    sniff(iface = interface_name, prn = process_traffic, store = 0)
    
def get_bigram_distribution_from_file(filename):
    bigram_dict = {} #Define bigram_dict
    total_bigrams = 0 #Set initial total to 0
    with open(filename, 'r') as f:
        for line in f:
            input_domain = tldextract.extract(line.rstrip())
            if len(input_domain.domain) > 5 and "-" not in input_domain.domain:
                for  bigram_position in range(len(input_domain.domain) - 1): #Run through each bigram in input_domain
                    total_bigrams = total_bigrams + 1
                    if input_domain.domain[bigram_position:bigram_position + 2] in bigram_dict:
                        bigram_dict[input_domain.domain[bigram_position:bigram_position + 2]] = bigram_dict[input_domain.domain[bigram_position:bigram_position + 2]] + 1 #Increment dictionary value by 1
                    else:
                        bigram_dict[input_domain.domain[bigram_position:bigram_position + 2]] = 1
    print(f"INFO: Total bigrams: {total_bigrams}") 
    return bigram_dict

def process_data(bigram_dict, total_bigrams):
    percentage_list_alexa = []
    with open("dga_data/alexa.txt",'r') as f:
        for line in f:
            input_domain = line.rstrip()
            input_domain = tldextract.extract(input_domain)
            if len(input_domain.domain) > 5 and "-" not in input_domain.domain:
                percentage = [] #Clear percentage list
                for  bigram_position in range(len(input_domain.domain) - 1):
                    if input_domain.domain[bigram_position:bigram_position + 2] in bigram_dict: #Check if bigram is in dictionary 
                        percentage.append((bigram_dict[input_domain.domain[bigram_position:bigram_position + 2]] / total_bigrams) * 100) #Get bigram dictionary value and convert to percantage
                    else:
                        percentage.append(0) #Bigram value is 0 as it doesn't exist
                percentage_list_alexa.append(scipy.mean(percentage))
                
    data = open('dga_data/dga_training.txt').read().splitlines()
    percentage_list_dga = [] #Define average_percentage
    for input_domain in range(len(data)): #Run through each input_domain in the data
        input_domain = tldextract.extract(data[input_domain])
        if len(input_domain.domain) > 5 and "-" not in input_domain.domain:
            percentage = [] #Clear percentage list
            for  bigram_position in range(len(input_domain.domain) - 1): #Run through each bigram in the data
                if input_domain.domain[bigram_position:bigram_position + 2] in bigram_dict: #Check if bigram is in dictionary 
                    percentage.append((bigram_dict[input_domain.domain[bigram_position:bigram_position + 2]] / total_bigrams) * 100) #Get bigram dictionary value and convert to percantage
                else:
                    percentage.append(0) #Bigram value is 0 as it doesn't exist

            percentage_list_dga.append(scipy.mean(percentage)) #Add percentage value to list for total average
    print("Total Average Percentage Alexa:", scipy.mean(percentage_list_alexa), "( Min:", min(percentage_list_alexa), "Max:", max(percentage_list_alexa), ")" )#Get average percentage
    print("Total Average Percentage DGA:", scipy.mean(percentage_list_dga), "( Min:", min(percentage_list_dga), "Max:", max(percentage_list_dga), ")") #Get average percentage
    print("Baseline:", (((scipy.mean(percentage_list_alexa) - scipy.mean(percentage_list_dga)) / 2) + scipy.mean(percentage_list_dga)))
    config_dict = { "percentage_alexa" : scipy.mean(percentage_list_alexa), 
                "percentage_dga" : scipy.mean(percentage_list_dga), 
                "baseline": ((scipy.mean(percentage_list_alexa) - scipy.mean(percentage_list_dga)) / 2) + scipy.mean(percentage_list_dga),
                "total_bigram": total_bigrams}
    with open("dga_data/config.json","w") as f:
        json.dump(config_dict, f)

def train(filename):
    if not os.path.isfile("dga_data/config.json"):
        if not os.path.isfile("dga_data/database.json"):
            bigram_dict = get_bigram_distribution_from_file(filename)
            with open("dga_data/database.json", 'w') as f:
                json.dump(bigram_dict,f)
        else:
            with open("dga_data/database.json", 'r') as f:
                bigram_dict = json.load(f)
        total_bigrams = sum(bigram_dict.values())
        process_data(bigram_dict, total_bigrams)
        
def test(filename):
    with open("dga_data/config.json","r") as f:
        x = json.load(f)
    baseline = x["baseline"]
    total_bigrams_settings = x["total_bigram"]
    
    with open('dga_data/database.json', 'r') as f:
        bigram_dict = json.load(f)

    data = open(filename).read().splitlines()
    flag = 0
    total_flags = 0
    percentage = []
    
    for input_domain in range(len(data)): #Run through each input_domain in the data
        input_domain = tldextract.extract(data[input_domain])
        if len(input_domain.domain) > 5 and "-" not in input_domain.domain:
            for  bigram_position in range(len(input_domain.domain) - 1): #Run through each bigram in the data
                if input_domain.domain[bigram_position:bigram_position + 2] in bigram_dict: #Check if bigram is in dictionary
                    percentage.append((round(((bigram_dict[input_domain.domain[bigram_position:bigram_position + 2]] / total_bigrams_settings) * 100), 2))) #Get bigram dictionary value and convert to percantage
                else:
                    percentage.append(0) #Bigram value is 0 as it doesn't exist
            

            total_flags = total_flags + 1

            if baseline >= scipy.mean(percentage):
                flag = flag + 1
        percentage = [] #Clear percentage list
    print("Detection Rate:", flag / total_flags * 100)

def check_domain(input_domain):
    with open("dga_data/config.json","r") as f:
        x = json.load(f)
    baseline = x["baseline"]
    total_bigrams_settings = x["total_bigram"]

    if os.path.isfile('dga_data/database.json'):
        with open('dga_data/database.json', 'r') as f:
            try:
                bigram_dict = json.load(f)
            # if the file is empty the ValueError will be thrown
            except ValueError:
                bigram_dict = {}

    percentage = []

    for  bigram_position in range(len(input_domain) - 1): #Run through each bigram in the data
        if input_domain[bigram_position:bigram_position + 2] in bigram_dict: #Check if bigram is in dictionary 
            percentage.append((bigram_dict[input_domain[bigram_position:bigram_position + 2]] / total_bigrams_settings) * 100) #Get bigram dictionary value and convert to percantage
        else:
            percentage.append(0) #Bigram value is 0 as it doesn't exist

    if baseline >= scipy.mean(percentage):
        return 1
    else:
        return 0

#train("dga_data/alexa.txt")  
#test("dga_data/test_domains.txt")
#print(check_domain("google.com"))

#enp81s0f0
interface_name = sys.argv[1]
capture_traffic(interface_name)