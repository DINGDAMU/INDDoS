#!/bin/bash

# Copyright 2013-present Barefoot Networks, Inc. 
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

#THIS_DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

#source $THIS_DIR/../../env.sh

#CLI_PATH=$BMV2_PATH/targets/simple_switch/sswitch_CLI

echo "Switch 10.0.1.1"
#echo "table_add set_heavy_hitter_count_table set_heavy_hitter_count 10.0.0.1/32 => " | $CLI_PATH heavy_hitter.json 22222


echo "displaying occSlots1"
echo "register_read occSlots1" | docker exec  -i hh simple_switch_CLI --thrift-port 22222
echo
echo "displaying occSlots2"
echo "register_read occSlots2" | docker exec  -i hh simple_switch_CLI --thrift-port 22222
echo
echo "displaying occSlots3"
echo "register_read occSlots3" | docker exec  -i hh simple_switch_CLI --thrift-port 22222
echo


