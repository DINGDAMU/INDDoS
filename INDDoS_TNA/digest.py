################################################################################
# BAREFOOT NETWORKS CONFIDENTIAL & PROPRIETARY
#
# Copyright (c) 2019-present Barefoot Networks, Inc.
#
# All Rights Reserved.
#
# NOTICE: All information contained herein is, and remains the property of
# Barefoot Networks, Inc. and its suppliers, if any. The intellectual and
# technical concepts contained herein are proprietary to Barefoot Networks, Inc.
# and its suppliers and may be covered by U.S. and Foreign Patents, patents in
# process, and are protected by trade secret or copyright law.  Dissemination of
# this information or reproduction of this material is strictly forbidden unless
# prior written permission is obtained from Barefoot Networks, Inc.
#
# No warranty, explicit or implicit is provided, unless granted under a written
# agreement with Barefoot Networks, Inc.
#
################################################################################


from scapy.all import Ether, IP, sendp, TCP, Raw, UDP



p4 = bfrt.myDDoS3.pipe
p4learn = bfrt.myDDoS3.learn.pipe.IngressDeparser
def my_learning_cb(dev_id, pipe_id, direction, pasrser_id, session,  msg):
    global p4
    print(msg)
    for digest in msg:
        print(digest)
        dstIP = digest["dst_addr"]
        print(dstIP)
    return 0

try:
        p4learn.digest.callback_deregister()
except:
        pass
finally:
        print("Deregistering old learning callback (if any)")
p4learn.digest.callback_register(my_learning_cb)
print("callback register is running")

