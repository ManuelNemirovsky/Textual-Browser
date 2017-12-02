from scapy.all import *
import netifaces
from time import gmtime, strftime , localtime
from termcolor import *
import turtle

dns_table = {'URL': [], 'IP': [], 'TIME': []}
dns_table_file = open('dns_table.txt', 'w+')

web_history = {'WEB SITE': [], 'TIME': []}
web_history_file = open('webHistory.txt', 'w+')

CACHE_LIST = []

def Get_Gateway():
    GATEWAY = netifaces.gateways() #getting all the gateways

    return GATEWAY['default'][netifaces.AF_INET][0] #taking the one that we can find his mac address


"""
    This function returns the MAC address of a given IP address
"""
def ARP_Req(ip_string):

    arp_pack = sr1(ARP(op=ARP.who_has, pdst=ip_string), timeout = 2, verbose = False)

    if arp_pack is not None and "ARP" in arp_pack:
        mac = arp_pack[ARP].hwsrc

    print "The MAC address is : ", mac
    return mac

"""
    This function Creates a DNS Query to 8.8.8.8 and returns the IP
"""
def DNS_Req(URL):

    global CACHE_LIST

    dns = sr1(IP(dst="8.8.8.8") / UDP(dport = 53) / DNS(rd=1, qd=DNSQR(qname=URL)), verbose=False)

    time =  strftime("%a, %d %b %Y %H:%M:%S", localtime())  #Take local time

    ip_list = []

    dns_table['URL'].append(URL)
    dns_table['TIME'].append(strftime("%Y-%m-%d %H:%M:%S", gmtime()))

    with open("dns_table.txt", 'w+') as dns_table_file:
        dns_table_file.write("URL : \n" + "\n".join(dns_table['URL']) + "\n\nIP:\n\n" + "\n".join(dns_table['IP']) + "\n\nTIME\n\n" + "\n".join(dns_table['TIME']) )

    for ans in dns["DNS"]:  #Go over DNS packet
        for i in range(0, ans["DNS"].ancount):  #The range is 0 - number of answers
            if ans.an[i].type == 1:  #Check if host
                CACHE_LIST.append(ans.an[i].rdata)   #adding each ip to the list
                ip_list.append(ans.an[i].rdata)
                dns_table['IP'].append(ans.an[i].rdata)

    return ip_list


#This function returns the IP of the URL from the internal DNS table if exist, else return - 0
def Ret_From_Cache(URL):
    index = 0
    while index < len(dns_table['URL']):
        if dns_table['URL'][index] == URL:
            return (dns_table['IP'][index])
        index += 1
    return 0

"""
    This function delete all content of the DNS file and the content of the DNS table.
"""
def Flush_DNS():
    dns_table.clear()
    with open("dns_table.txt", 'w+') as dns_table_file:
        dns_table_file.write("")

"""
    This function update the history table and file by adding the URL and time of visiting(current time)
"""
def Update_history(URL):
    web_history['WEB SITE'].append(URL)
    web_history['TIME'].append(strftime("%Y-%m-%d %H:%M:%S", gmtime()))
    with open("webHistory.txt", 'w+') as web_history_file:
        web_history_file.write("Web Sites : \n" + "\n" .join(web_history['WEB SITE']) + "\n\nTIME:\n\n" + "\n".join(web_history['TIME']))

"""
    This function removes all the data in the history table and file
"""
def Clear_History():

    #delete all of the values inside the keys in the dict
    for value in web_history.values():
        del value[:]

    with open("webHistory.txt", 'w+') as web_history_file:
        web_history_file.write("Web Sites:\n\nTime:\n\n")


"""
    This function remove all the records of the given URL from the History table and file
"""
def Remove_From_History(URL):
    index = 0
    while index < len(web_history['WEB SITE']):
        if web_history['WEB SITE'][index] == URL:
            del web_history['WEB SITE'][index]
            del web_history['TIME'][index]
        with open("webHistory.txt", 'w+') as web_history_file:
            web_history_file.write("Web Sites : \n" + "\n".join(web_history['WEB SITE']) + "\n\nTIME:\n\n" + "\n".join(web_history['TIME']))
        index += 1


"""
    The functions uses the functions "Ret_From_Cache" and "DNS_Req" to find the IP address of a given URL
"""
def Find_IP(URL):
    answer = Ret_From_Cache(URL)

    if answer != 0 and answer != None:  #Check if the ip found in cache
        return answer

    else:  #If ip address didn't found in cache
        answer = DNS_Req(URL)
        return answer

"""
    this function will get a URL and will solve its IP address using the "find_ip" function and create an HTTP GET message to this site,
    send it and save the data out of the received packet to an html file.
"""
def Make_GET(URL):
    Update_history(URL)

    ip = Find_IP(URL)
    
    if isinstance(ip, str) == True:  #Check if ip is a string and not a list of several ip addresses
        get(URL, ip)

    else:  #Case that ip is a list of several ip addresses
        get(URL, ip[0])
    


def get(url , ip):
    HTTP_OK = "200 OK"

    # Send Syn Packet
    sport = random.randint(10000, 16000)
    seq = random.randint(10000, 200000)

    syn_pack = IP(dst=ip) / TCP(dport=80, seq=seq, flags='S', sport=sport)
    ack_syn_pack = sr1(syn_pack, verbose=1, timeout=5)
    recv_seq = ack_syn_pack[TCP].seq

    # add 1 to seq number and ack number for the ack packet
    current_seq = seq + 1
    current_ack = recv_seq + 1

    # send ack packet
    ack_pack = IP(dst=ip) / TCP(dport=80, window=ack_syn_pack[TCP].window, seq=current_seq, ack=current_ack, flags='A', sport=sport)
    send(ack_pack, verbose=1)

    http_get = 'GET / HTTP/1.1\r\nHost: ' + url + '\r\nConnection: keep-alive\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\nAccept-Encoding: none \r\nAccept-Language: en-US,en;q=0.8\r\n\r\n'

    get_pack = IP(dst=ip) / TCP(dport=80, seq=current_seq, ack=current_ack, flags='PA', sport=sport, window = ack_syn_pack[TCP].window) / Raw(http_get)

    get_ans = sr(get_pack , verbose = 1 , timeout = 5 , multi = 1)

    out = open("outPut.html" , "w")

    all_ans = get_ans[0]
    for ans in all_ans:
        if Raw in ans[1]:
            raw_data = str(ans[1][Raw])
            if HTTP_OK in raw_data:
                end_of_http_headers = raw_data.find("\r\n\r\n")
                out.write(raw_data[end_of_http_headers:])
    out.close()

#this function will open a menu that contains the following options :
#1. Show History
#2. Clear History
#3.Remove specific record //
def History_menu():
    loop = 1
    while loop == 1:
        cprint('\t\tChose one of the options:' , 'magenta' , attrs=['bold'])
        ans = raw_input(colored('\n1. Show History\n2. Clear History\n3.Remove specific record\n4.go back to the menu\n' , 'green'))
        ans = int(ans)
        if ans == 1:
            show_history()
        elif ans == 2:
            Clear_History()
            print colored("\n\n\t\t**Your history has been cleared**\n\n" , 'blue')
        elif ans == 3:
            url_addres = raw_input(colored('Enter the URL you want to remove: \n' , 'green'))
            Remove_From_History(url_addres)
            print colored('\n\n\t\t**Done**\n' , 'grey')
        elif ans == 4:
            loop = 0
            print "\n\n"
        else:
            cprint('\t\t**please enter a value from 1 to 4**' , 'red' , attrs=['bold']) 

#Nice and smooth history menu
def show_history():
    web_url = web_history.get('WEB SITE')
    time = web_history.get('TIME')
    index = 0
    
    print "\n\n"

    #using this method only because I know that the number of the 
    #web url list is equal to the number of the time list
    while index < len(web_url):
        print "\n" + web_url[index] + " : " + time[index]
        index += 1

    print "\n"


"""
    This function will show the browser's menu who contains the following options :
    1. history
    2. visit a site
    3. credits
    4. exit
"""
def Menu():
    loop = 1
    while loop == 1:
        cprint('\n\t\tWelcome to my textual browser\n\t\tWhat would you like to do?' , 'cyan' , attrs=['bold'])
        choice = raw_input(colored('\n1. history \n2. visit a site\n3. credits\n4.Exit\n' , 'cyan'))
        choice = int(choice)
        if choice == 1:
            History_menu()
        elif choice == 2:
            url = raw_input(colored("Enter a url address: " , 'blue'))
            Make_GET(url)
        elif choice == 3:
            cprint('\nManuel Nemirovsky => Software Developer\nMika Gross => Software Developer\n' , 'green' , attrs=['bold'])
        elif choice == 4:
            cprint('\t\tSee you next time :)\n\n' , 'yellow' , attrs=['bold'])
            smiley()
            loop = 0
        else:
            cprint('\t\t**please enter a value from 1 to 4**' , 'red' , attrs=['bold']) 


#nice function for the end :D
def smiley():
    smiles = turtle.Turtle()    
    turtle.bgcolor("yellow")
    smiles.penup()
    smiles.goto(-75,150)
    smiles.pendown()
    smiles.circle(10)     #eye one

    smiles.penup()
    smiles.goto(75,150)
    smiles.pendown()
    smiles.circle(10)     #eye two

    smiles.penup()
    smiles.goto(0,0)
    smiles.pendown()
    smiles.circle(100,90)   #right smile

    smiles.penup()           
    smiles.setheading(180) # <-- look West
    smiles.goto(0,0)
    smiles.pendown()
    smiles.circle(-100,90)


    smiles.goto(100, 100)

def main():
    Menu()
main()
