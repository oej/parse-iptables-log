# Parse IPtables logs
# Based on code from https://github.com/jakgibb/parse-iptables-log
# released under the "Do What The F*ck You Want To Public License" 

# Modified by Olle E. Johansson - oej@edvina.net
# 
import re
import fileinput
from collections import Counter

pair_re = re.compile('([^ ]+)=([^ ]+)')
portlist = []
iplist = []

for line in fileinput.input():
    line = line.rstrip()
    data = dict(pair_re.findall(line))
    date = line.split()
    print("DEBUG: Data {}".format(data))
    if data.get('DPT', None) == None:
        plabel="PROTO"
        pvalue=data['PROTO']
        protolabel=data['PROTO']
        portlist.append(protolabel)
    else:
        print("DEBUG: Data DPT {}".format(data['DPT']))
        plabel="Dport"
        pvalue=data['DPT']
        protolabel=data['PROTO'] + "/" + data['DPT']
        portlist.append(protolabel)
    if data.get('SPT', None) == None:
        splabel=""
        spvalue=""
    else:
        splabel="SPT"
        spvalue=data['SPT']
    iplist.append(data['SRC'])
    print(date[0]+" "+date[1]+" "+date[2]+" ",)
    print(data['PROTO'], "\t",plabel, pvalue, "\t",splabel, spvalue, "\tSRC:", data['SRC'], "\tDST",data['DST'])

try:
    print("\n")
    count = 0
    linesToShow = 10
    while (count < linesToShow):
        portcommon = [ite for ite, it in Counter(portlist).most_common()]
        print ("Port: "+str(portcommon[count])+" had "+str(portlist.count(portcommon[count]))+" hits")
        count = count + 1

except IndexError:
    print("")

try:
    print("\n")
    count = 0
    while (count < linesToShow):
        ipcommon = [ite for ite, it in Counter(iplist).most_common()]
        print("IP: "+str(ipcommon[count])+" had "+str(iplist.count(ipcommon[count]))+" hits")
        count = count + 1
except IndexError:
    print ("")
print("\n")
