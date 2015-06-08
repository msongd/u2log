# u2log
Dump Snort unified2 to json ...
Not support IPv6 event for now

Usage:
u2log '-f=samples/snort_unified.log.*' -o=/tmp/a.json -w=/tmp/a.w

- Parse samples/snort_unified.log.*
- output json line by line to /tmp/a.json
- mark progress to file /tmp/a.w

Cron:

*/10 * * * * sleep `bash -c 'echo $(($RANDOM \% 500))'` ; /usr/local/bin/u2log -f='/var/log/snort/eth1/snort_unified.log.*' -l=/var/log/snort/eth1/u2log.log -o=/var/log/snort/eth1/u2log.json -w=/var/log/snort/eth1/u2log.w > /tmp/eth1_stdout.log 2>&1

- Exec u2log every 10 mins, with random sleep
- u2log will parse snort_unified.log.* file
- since progress is marked in u2log.w file, next cron run will only parse new event since last time.
- Each event will be a json document in 1 line, see sample below

A sample json line:

{"Sensor_id":0,"Event_id":393220,"Second":1432525297,"Microsecond":881046,"Sig_id":12,"Gen_id":129,"Sig_rev":1,"Cls_id":3,"Pri_id":2,"Ip_src":"x.x.x.x","Ip_dst":"x.x.x.x","Sport":443,"Dport":53207,"Proto":6,"Impact_flag":0,"Impact":0,"Blocked":0,"Mpls_label":0,"VlanId":0,"Pad2":0,"App":"https","Packets":[{"Sensor_id":0,"Event_id":393220,"Event_second":1432525297,"Packet_second":1432525297,"Packet_microsecond":881046,"Linktype":1,"Packet_length":103,"SrcMac":[x,x,x,x,x,x],"DstMac":[x,x,x,x,x,x],"EthType":2048,"Byte1":69,"Byte2":0,"PacketLen":89,"ID":22598,"Byte3":64,"Byte4":0,"TTL":64,"Proto":6,"Chksum":24498,"SrcIP":[x,x,x,x],"DstIP":[x,x,x,x],"Data":"AbvP1yu/+nKdHNVHgBgANp94AAABAQgKLoGHpQCNTHAVAwEAIAkRh+sqG4W6NqIZv9SIf0N1hIPs9KD8ABN8aC5MOFO7"}],"ExtraData":null}

Data in "Packets" array is in Base64 encoded
