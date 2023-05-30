#!/usr/bin/env python
# coding: utf-8

# In[79]:


class jsonParserNetwork:
    def __init__(self):
        pass
    def parseTcpTraffic(self,tcp_data):
        tcp_data = tcp_data.strip()
        traffic_list = tcp_data.split("\n")
        #print(traffic_list)
        pkt_num = 0
        traffic_dict = {}
        for pkt in traffic_list:
            if pkt == "":
                continue
            pkt_num = pkt_num + 1
            pkt = ((pkt.split("IP"))[1]).strip()
            values = pkt.split(">")
            source_value = values[0].split(".")
            source_port = int(source_value[4].strip())
            source_ip = ""
            for val in (source_value)[:-1]:
                source_ip = source_ip + "." + val
            source_ip = source_ip[1:]
            destination_values = ((values[1].split(":")[0]).strip()).split(".")
            pkt_payload = int(((values[1].split(":")[1]).strip()).split(" ")[1])
            destination_port = int(destination_values[4])
            destination_ip = ""
            for val in destination_values[:-1]:
                destination_ip = destination_ip + "." + val
            destination_ip = destination_ip[1:]
            pkt_dict = {
                "source_ip" : source_ip,
                "source_port" : source_port,
                "destination_ip" : destination_ip,
                "destination_port" : destination_port, 
                "packet_payload" : pkt_payload
            }
            traffic_dict[pkt_num] = pkt_dict
        return traffic_dict
    '05:05:07.109882 IP 192.168.56.101.55872 > 8.8.8.8.53: 26625+ [1au] A? irc.xitenet.org. (44)'
    def parseDnsTraffic(self,dns_data):
        dns_data = dns_data.strip()
        traffic_list = dns_data.split("\n")
        #print(traffic_list)
        pkt_num = 0
        traffic_dict = {}
        for pkt in traffic_list[:-1]:
            pkt_num = pkt_num + 1
            pkt = (pkt.split("IP")[1]).strip()
            values = pkt.split(">")
            source_value = (values[0].strip()).split(".")
            source_port = int(source_value[4])
            source_ip = ""
            for val in source_value[:-1]:
                source_ip = source_ip + "." + val
            source_ip = source_ip[1:]
            destination_values = ((values[1].split(":")[0]).strip()).split(".")
            destination_port = int(destination_values[4])
            destination_ip = ""
            for val in destination_values[:-1]:
                destination_ip = destination_ip + "." + val
            destination_ip = destination_ip[1:]
            pkt_attr = (((values[1].split(":"))[1]).strip()).split()
            query_id = (pkt_attr[0]).strip()
            std_query = False
            if query_id[-1] == "+":
                std_query = True
            query_type = ""
            domain_name = ""
            pkt_payload = ""
            QNAME = None
            if len(pkt_attr)==4:
                query_type = (pkt_attr[1]).strip()
                domain_name = (pkt_attr[2]).strip()
                pkt_payload = int((pkt_attr[3][1:-1]).strip())
            else:
                QNAME = (pkt_attr[1]).strip()
                query_type = (pkt_attr[2]).strip()
                domain_name = (pkt_attr[3]).strip()
                pkt_payload = int((pkt_attr[4][1:-1]).strip())
                
                

            pkt_dict = {
                "source_ip" : source_ip,
                "source_port" : source_port,
                "destination_ip" : destination_ip,
                "destination_port" : destination_port,
                "query_identification_number" : query_id,
                "QNAME" : QNAME,
                "query_type" : query_type,
                "standard_query_flag" : std_query,
                "domain_name" : domain_name,
                "packet_payload" : pkt_payload,
            }
            traffic_dict[pkt_num] = pkt_dict

        return traffic_dict


# In[81]:


# t = jsonParserNetwork()
# d= t.parseDnsTraffic(nw)
# print(d)


# In[45]:


# tcp_data = nw
# traffic_list = tcp_data.split("\n")
# pkt_num = 0
# traffic_dict = {}
# for pkt in traffic_list:
#     if pkt == "":
#         continue
#     pkt_num = pkt_num + 1
#     pkt = pkt[19:]
#     values = pkt.split(">")
#     source_value = values[0].split(".")
#     source_port = int(source_value[4].strip())
#     source_ip = ""
#     for val in (source_value)[:-1]:
#         source_ip = source_ip + "." + val
#     source_ip = source_ip[1:]
#     destination_values = ((values[1].split(":")[0]).strip()).split(".")
#     pkt_payload = int(((values[1].split(":")[1]).strip()).split(" ")[1])
#     destination_port = int(destination_values[4])
#     destination_ip = ""
#     for val in destination_values[:-1]:
#         destination_ip = destination_ip + "." + val
#     destination_ip = destination_ip[1:]
#     pkt_dict = {"source_ip" : source_ip, "source_port" : source_port,
#                 "destination_ip" : destination_ip, "destination_port" : destination_port, 
#                "packet_payload" : pkt_payload }
#     traffic_dict[pkt_num] = pkt_dict
# print(traffic_dict)
    
    
    


# In[78]:


# dns_data = t[0].decode()

# traffic_list = dns_data.split("\n")
# pkt_num = 0
# traffic_dict = {}
# for pkt in traffic_list[:-1]:
#     pkt_num = pkt_num + 1
#     pkt = (pkt.split("IP")[1]).strip()
#     values = pkt.split(">")
#     source_value = (values[0].strip()).split(".")
#     source_port = int(source_value[4])
#     source_ip = ""
#     for val in source_value[:-1]:
#         source_ip = source_ip + "." + val
#     source_ip = source_ip[1:]
#     destination_values = ((values[1].split(":")[0]).strip()).split(".")
#     destination_port = int(destination_values[4])
#     destination_ip = ""
#     for val in destination_values[:-1]:
#         destination_ip = destination_ip + "." + val
#     destination_ip = destination_ip[1:]
#     pkt_attr = (((values[1].split(":"))[1]).strip()).split()
#     query_id = (pkt_attr[0]).strip()
#     std_query = False
#     if query_id[-1] == "+":
#         std_query = True
#     query_type = (pkt_attr[1]).strip()
#     domain_name = (pkt_attr[2]).strip()
#     pkt_payload = int((pkt_attr[3][1:-1]).strip())
#     pkt_dict = {
#         "source_ip" : source_ip,
#         "source_port" : source_port,
#         "destination_ip" : destination_ip,
#         "destination_port" : destination_port,
#         "query_identification_number" : query_id,
#         "query_type" : query_type,
#         "standard_query_flag" : std_query,
#         "domain_name" : domain_name,
#         "packet_payload" : pkt_payload,
#     }
#     traffic_dict[pkt_num] = pkt_dict
    
# print(traffic_dict)


# In[ ]:




