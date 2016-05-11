#/*
# * Copyright (c) 2015-2016 Freescale Semiconductor, Inc. All rights reserved.
# */

help() {
	echo
	echo "USAGE: . ./loopback_sanity_test.sh <options>
The Options are:
	-a		Auto mode		Enabling the Auto mode. Default is manual
						mode.

	-c		Cunit			Enabling Cunit testing.

	-p=\"num\"	Ping packets numbers	'num' is number of ping packets which will be used
						for sanity testing. Default is 10.

	-d		Developer help		This option is only for developers. It will
						print the help for developers, which describes
						how to add a test case in the script.

	-h		Help			Prints script help.

Example:
	. ./loopback_sanity_test.sh -a        OR     source ./loopback_sanity_test.sh -a

Options and Sanity script running behaviour:

	OPTIONS					SCRIPT BEHAVIOUR

	* Both -a and -c			If both options -a and -c are given, then script will
						run all the test cases automatically including Cunit
						test cases.

	* only -a				If only this option specified, then script will run
						all the ODP example applications automatically and at the
						end an option will be given to the user which specify whether
						to test the Cunit or not. If user press 'y' then script will
						run all the Cunit test cases automatically also.

	* only -c				If only this option specified, then script will run only
						Cunit test cases. An option will be given to the user
						which will describes that whether to run the script in auto mode
						or not.

	* neither -c nor -a			If none of these options is there, then script will run in manual
						mode even for Cunit test cases.


Assumptions:
	* dynamic_dpl.sh, kernel-ni.sh and loopback_sanity_test.sh all these three scripts
	  are present in the 'usr/odp/scripts' directory.
	* All ODP example binaries are present in the '/usr/odp/bin' directory.
	* All ODP Cunit binaries are present in the '/run' directory.
	* odpfsl_kni.ko is present in any of the child directory of '/lib/' for odp_kni_demo testing.
	* There are sufficient resources available to create two ODP conatiners and 3 kernel interfaces.
	* There is sufficient memory to run two odp applications concurrently. Script is verified with
	  following bootargs:
	  (bootargs=console=ttyS1,115200 root=/dev/ram0 earlycon=uart8250,mmio,0x21c0600,115200
	   ramdisk_size=2000000 default_hugepagesz=2m hugepagesz=2m hugepages=256)

Note:	Minimum running time of script for all test cases is 30 mins.
	"

}

developer_help() {
	echo
	echo -e "\tDeveloper's Help:

	###############################################################################
	############ Sanity script will have following Resources ######################
	###############################################################################
	3 kernel interfaces and 2 containers will be created for the testing, having
	following number of DPNIs objects:

	KERNEL => NI, NI2, NI3
	FDPRC => FDPNI0, FDPNI1, FDPNI2
	SDPRC => SDPNI0, SDPNI1

	These DPNIs will be connected as:

		________________________________________________
	       |			___________________     |
	       |		       |		   |    |
	   NI3 |		FDPNI1 |	    SDPNI0 |    | SDPNI1
	==============		==============          ============
	|   kernel   |		|   FDPRC    |		|   SDPRC  |
	|	     |		|	     |		|          |
	==============		==============		============
	NI |	  | NI2	     FDPNI2|	| FDPNI0	      /\
	   |	  |________________|	|		      \/ SDPNI2
	   |____________________________|

	SDPNI2 will be Connected to itself

	MAC addresses to these DPNIs will be as:

	NI  = 00:00:00:00:08:01
	NI2 = 00:00:00:00:08:02
	NI3 = 00:00:00:00:08:03

	FDPNI0 = 00:00:00:00:5:1
	FDPNI1 = 00:00:00:00:5:2
	FDPNI2 = 00:00:00:00:5:3

	SDPNI0 = 00:00:00:00:6:1
	SDPNI1 = 00:00:00:00:5:2
	SDPNI2 = 00:00:00:00:4:3

	Namespaces and kernel interfaces:

	* Interface NI will be in the default namespace having IP address 192.168.111.2
	* Interface NI2 will be in 'sanity_ns' namespace having IP address 192.168.222.2
	* Interface NI3 will be in 'sanity_ipsec_ns' namespace having IP address 192.168.222.2

ODP EXAMPLE APPLICATIONS: Method to add an ODP example application as test case:

Test case command syntax:
	run_command <arguments ...>

Mandatory arguments:
	argument1	Test module	First argument should be Test Module, which is predefined
					Macro for each odp application as:
					PKTIO      => odp_pktio
					REFLECTOR  => odp_reflector
					KNI	   => odp_kni_demo
					L3FWD	   => odp_l3fwd
					GENERATOR  => odp_generator
					CLASSIFIER => odp_classifier
					IPSEC	   => odp_ipsec
					IPSEC_PROTO=> odp_ipsec_proto
					TIMER	   => odp_timer

	argument2	command		Actual command to run.
	argument3	command2	Only mandatory for 'odp_ipsec' test cases.

Optional arguments:
	There are some optional arguments that can only be used for 'odp_ipsec' and 'odp_ipsec_proto'
	applications.
	-p		MODE		To enable the ODP_IPSEC_USE_POLL_QUEUES
	-s		MODE		To enable the HASH and SCHED_PUSH
	-i='x'		INFO		User information, helpful for test reports,
					where x is the information
	-o		INTEROPS	To enable the interops testing, only valid for
					'odp_ipsec_proto' application.

Process of testing:
	* odp_pktio, odp_reflector and odp_kni_demo:
		---- ping with destination 192.168.111.1, packets will go through NI, so only FDPNI0 is valid
		     for testing. Results are based on %age packets received.

	* odp_l3fwd
		---- with iperf, only FDPNI0 and FDPNI1 should be used for testing. Results are based on
		     %ge packets loss while iperf testing.

	* odp_generator
	        ---- for ping mode, results will be based on number of icmp packets received by application. Only FDPNI0
		     must be used for testing with source IP 192.168.111.1
		---- with iperf, for recieve mode, only FDPNI0 should be used. Results are based on UDP packets
		     received by the application
	        ---- with tcpdump, for send mode. tcpdump will be running on NI, so only FDPNI0 should be used
		     for testing. Results will be based on number of UDP packets captured by tcpdump.

	* odp_classifier
		---- with ping, in the testing only source ip is classified yet, results are based
		     on the counter value of queue1. Only FDPNI0 should be used.

	* odp_timer
		---- Results are based on the number of events received. Time will not be the parameter for results.

	* odp_ipsec
		---- with ping from NI to NI3 interface. For command1 FDPNI0 and FDPNI1 and for command2 SDPNI0 and SDPNI1
		     are valid interfaces for testing.

	* odp_ipsec_proto
		---- with ping from NI to NI3 interface. For interops testing only command1 is required having DPNIs
		     FDPNI0 and FDPNI2.

Example:
	run_command PKTIO \"./odp_pktio -c 8 -m 0 -i \$FDPNI0\"

	All these commands should be added only in run_odp() function.


ODP CUNIT APPLICATIONS: Method to add an Cunit application as test case:

Test case command syntax:
	run_cunit_command <argument>

	Where argument is actual command to run.
	SDPRC will be used for CUNIT testing

Example:

	run_cunit_command \"./init_main_ok\"

	This command should only be added in run_cunit() function.

Results:
	Cunit results will be based on the failed test_suites/test_cases showing in the application logs
	"
}

#/* Function to append new lines into sanity_log file*/
append_newline() {
	num=0
	while [[ $num -lt $1 ]]
	do
		echo >> sanity_log
		num=`expr $num + 1`
	done
}

#Checking if resources are already available
check_resources () {
	#checking kernel interfaces are available or not.
	if [[ -z $NI || -z $NI2 ]]
	then
		return 1;
	fi

	#checking sanity script containers
	if [[ -z $FDPRC || -z $FDPNI0 || -z $FDPNI1 || -z $FDPNI2 ]]
	then
		return 1;
	fi
	if [[ -z $SDPRC || -z $SDPNI0 || -z $SDPNI1 || -z $SDPNI2 ]]
	then
		return 1;
	fi

	return 0;
}

#creating the required resources
get_resources() {
	#/*
	# * creating the container "FDPRC" with 3 DPNIs which will not be connected to
	# * any object.
	# */
	. ./dynamic_dpl.sh dpni dpni dpni
	FDPRC=$DPRC
	FDPNI0=$DPNI1
	FDPNI1=$DPNI2
	FDPNI2=$DPNI3

	#/*
	# * creating the 2nd container "SDPRC" with 2 DPNIs in which one will be connected to
	# * the first DPNI of first conatiner and 2nd DPNI will remain unconnected.
	# */
	. ./dynamic_dpl.sh $FDPNI1 dpni dpni-self
	SDPRC=$DPRC
	SDPNI0=$DPNI1
	SDPNI1=$DPNI2
	SDPNI2=$DPNI3

	#/*Creating the required linux interfaces and connecting them to the reaquired DPNIs*/

	./kernel-ni.sh $FDPNI0 | tee linux_iflog
	NI=`grep -o "interface: ni\w*" linux_iflog | sed -e 's/interface: //g'`

	./kernel-ni.sh $FDPNI2 | tee linux_iflog
	NI2=`grep -o "interface: ni\w*" linux_iflog | sed -e 's/interface: //g'`

	./kernel-ni.sh $SDPNI1 | tee linux_iflog
	NI3=`grep -o "interface: ni\w*" linux_iflog | sed -e 's/interface: //g'`

	rm linux_iflog
}


# Function to print results of the most of test cases.
print_result() {
	if [[ "$1" == "0%" ]]
	then
		echo -e $GREEN "\tno packet loss"$NC
		echo -e "\tNo packet loss  ----- PASSED" >> sanity_tested_apps
		passed=`expr $passed + 1`
	elif [[ "$1" == "100%" ]]
	then
		echo -e $RED "\t$1"" packets loss"$NC
		echo -e "\t""$1"" packets loss  ----- FAILED" >> sanity_tested_apps
		failed=`expr $failed + 1`
	elif [[ -z "$1" ]]
	then
		echo -e $RED "\tUnable to capture Results"$NC
		echo -e "\tunable to capture Results  ----- N/A" >> sanity_tested_apps
		na=`expr $na + 1`
	else
		echo -e $RED "\t$1"" packets loss"$NC
		echo -e "\t""$1"" packets loss  ----- PARTIAL PASSED" >> sanity_tested_apps
		partial=`expr $partial + 1`
	fi
}

#/* Function to run the odp_pktio and odp_reflector test cases*/
run_pktio() {
echo -e " #$test_no)\tTest case:$1    \t\tCommand:($2) "
echo
eval $PRINT_MSG
$READ
if [[ "$input" == "y" ]]
then
	echo -e " #$test_no)\t$1\t\tcommand ($2) " >> sanity_log
	echo -e " #$test_no)\tTest case:$1    \t\tCommand:($2) " >> sanity_tested_apps
	append_newline 1
	echo
	eval "$2 >> sanity_log 2>&1 &"
	echo
	sleep 3
	append_newline 3
	echo " Starting the ping test ..."
	ping 192.168.111.1 -c $ping_packets | tee log
	RESULT=`grep -o "\w*\.\w*%\|\w*%" log`
	echo
	cat log >> sanity_log
	print_result "$RESULT"
	pid=`ps | pgrep odp_pktio`
	if [[ -z "$pid" ]]
	then
		pid=`ps | pgrep odp_reflector`
	fi
	kill -2 $pid
	sleep 2
	append_newline 5
	rm log
	echo
	echo
	echo
	echo >> sanity_tested_apps
else
	echo -e " #$test_no)\tTest case:$1    \t\tCommand:($2) " >> sanity_untested_apps
	echo -e "\tNot Tested" | tee -a sanity_untested_apps
	not_tested=`expr $not_tested + 1`
	echo
	echo >> sanity_untested_apps
fi
test_no=`expr $test_no + 1`
}

#/* Function to test odp_timer_test*/

run_timer() {
echo -e " #$test_no)\tTest case:$1\t\t\tCommand:($2) "
echo
eval $PRINT_MSG
$READ
if [[ "$input" == "y" ]]
then
	echo -e " #$test_no)\t$1\t\tcommand ($2) " >> sanity_log
	echo -e " #$test_no)\tTest case:$1\t\t\tCommand:($2) " >> sanity_tested_apps
	append_newline 1
	echo -e "\tTesting is in progress ..."
	CORES=$(echo "$2" | grep -o "\-c\ \w*" | sed 's/-c //')
	TIMEOUTS=$(echo "$2" | grep -o "\-t\ \w*" | sed 's/-t //')
	PERIODS=$(echo "$2" | grep -o "\-p\ \w*" | sed 's/-p //')
	if [[ -z $PERIODS ]]
	then
		PERIODS=1
	else
		PERIODS=`expr $PERIODS / 1000000`
	fi
	COUNTS=`expr $CORES \* $TIMEOUTS`
	WAIT=`expr $TIMEOUTS \* $PERIODS + 10`
	echo
	eval "$2 > log 2>&1 &"
	echo
	sleep $WAIT
	pid=`ps | pgrep odp_timer_test`
	if [[ $pid ]]
	then
		kill -2 $pid
	fi
	sleep 2
	append_newline 3
	RESULT=`grep -c "timeout, tick" log`
	echo
	if [[ $RESULT == $COUNTS ]]
	then
		echo -e $GREEN "\t$RESULT Timeouts Received"$NC
		echo -e "\t$RESULT Timeouts Received  ----- PASSED" >> sanity_tested_apps
		passed=`expr $passed + 1`
	elif [[ $RESULT == 0 ]]
	then
		echo -e $RED "\t0 Timeouts Received"$NC
		echo -e "\t0 Timeouts Received  ----- FAILED" >> sanity_tested_apps
		failed=`expr $failed + 1`
	else
		echo -e $RED "\t$RESULT Timeouts Received"$NC
		echo -e "\t$RESULT Timeouts Received  ----- PARTIAL PASSED" >> sanity_tested_apps
		partial=`expr $partial + 1`
	fi
	cat log >> sanity_log
	sleep 2
	append_newline 5
	rm log
	echo
	echo
	echo
	echo >> sanity_tested_apps
else
	echo -e " #$test_no)\tTest case:$1\t\t\tCommand:($2) " >> sanity_untested_apps
	echo -e "\tNot Tested" | tee -a sanity_untested_apps
	not_tested=`expr $not_tested + 1`
	echo
	echo >> sanity_untested_apps
fi
test_no=`expr $test_no + 1`
}


#/* Function to run the odp_classifier test cases*/

run_classifier() {
echo -e " #$test_no)\tTest case:$1\t\tCommand:($2) "
echo
eval $PRINT_MSG
$READ
if [[ "$input" == "y" ]]
then
	echo -e " #$test_no)\t$1\t\tcommand ($2) " >> sanity_log
	echo -e " #$test_no)\tTest case:$1\t\tCommand:($2) " >> sanity_tested_apps
	append_newline 1
	echo
	eval "$2 > class_log 2>&1 &"
	echo
	sleep 3
	append_newline 3
	echo " Starting the ping test ..."
	ping 192.168.111.1 -c $ping_packets | tee log
	sleep 5
	OUTPUT=$(tail -1 class_log)
	OUTPUT=$(echo "$OUTPUT" | awk '{$2=$2};1')
	OUTPUT=$(echo "$OUTPUT" | tr -s ' ' '\n' | tail -5 | tr -s '\n' ' ')
	QUEUE1=$(echo "$OUTPUT" | cut -f1 -d ' ' | grep -o ..$)
	QUEUE2=$(echo "$OUTPUT" | cut -f2 -d ' ')
	QUEUE3=$(echo "$OUTPUT" | cut -f3 -d ' ')
	QUEUE4=$(echo "$OUTPUT" | cut -f4 -d ' ')
	QUEUE5=$(echo "$OUTPUT" | cut -f5 -d ' ')
	sent_packets=`expr $ping_packets \* 2`
	if [[ $QUEUE1 == $sent_packets ]]
	then
		echo -e $GREEN"\tTotal sent $sent_packets and Queue1 received $QUEUE1 packets"$NC
		echo -e "\tTotal sent $sent_packets and Queue1 received $QUEUE1 packets    ----- PASSED" >> sanity_tested_apps
		passed=`expr $passed + 1`
	else
		echo -e $RED"\tTotal sent $sent_packets and Queue1 received $QUEUE1 packets"$NC
		echo -e "\tTotal sent $sent_packets and Queue1 received $QUEUE1 packets    -----FAILED" >> sanity_tested_apps
		failed=`expr $failed + 1`
	fi
	echo
	pid=`ps | pgrep odp_classifier`
	kill -2 $pid
	sleep 2
	pid=`ps | pgrep odp_classifier`
	kill -9 $pid
	sleep 2
	cat class_log >> sanity_log
	append_newline 5
	rm log
	rm class_log
	echo
	echo
	echo
	echo >> sanity_tested_apps
else
	echo -e " #$test_no)\tTest case:$1\t\tCommand:($2) " >> sanity_untested_apps
	echo -e "\tNot Tested" | tee -a sanity_untested_apps
	not_tested=`expr $not_tested + 1`
	echo
	echo >> sanity_untested_apps
fi
test_no=`expr $test_no + 1`
}

unset_ipsec_macros() {
	unset ODP_IPSEC_USE_POLL_QUEUES
	unset HASH_DST
	unset ODP_SCH_PUSH_MODE
	unset ODP_SCH_PULL_MODE
	unset MODE
	unset INFO
	unset INTEROPS
	unset MODULE
	unset COMMAND1
	unset COMMAND2
}

#/* Function to run the odp_ipsec test cases*/

run_ipsec() {
for i in "$@"
do
	arg=$(echo "$i" | grep -o "odp_ipsec")
	if [[ -z $arg ]]
	then
		arg="$i"
	fi
	case $arg in
		-p )
			export ODP_IPSEC_USE_POLL_QUEUES="yes"
			MODE="ODP_IPSEC_USE_POLL_QUEUES"
			;;
	        -s )
			MODE="ODP_SCH_PUSH_MODE"
	                ;;
		IPSEC )
			MODULE="IPSEC"
			;;
		-i=*)
			INFO="${i#*=}"
			;;
	        odp_ipsec )
			if [[ -z $COMMAND1 ]]
			then
				COMMAND1="$i"
			else
				COMMAND2="$i"
			fi
			;;
	        *)
			echo -e " #$test_no)\t$MODULE\t\tMODE=>($MODE)\tINFO=>($INFO)\tcommand: ("$COMMAND1")\tCommand2: ("$COMMAND2")" >> sanity_log
			echo -e " #$test_no)\t$MODULE\t\tMODE=>($MODE)\tINFO=>($INFO)\tcommand: ("$COMMAND1")\tCommand2: ("$COMMAND2")" >> sanity_untested_apps
		        echo -e $i "\tInvalid Argument" | tee -a sanity_untested_apps
		        echo -e $i "\tInvalid Argument" | tee -a sanity_log
			echo -e "\tNot Tested" | tee -a sanity_untested_apps
			not_tested=`expr $not_tested + 1`
			echo >> sanity_untested_apps
			unset_ipsec_macros
			test_no=`expr $test_no + 1`
			return
		        ;;
	esac
done

if [[ -z $MODE ]]
then
	export ODP_SCH_PULL_MODE=1
	MODE="ODP_SCH_PULL_MODE"
fi


echo -e " #$test_no)\tTest case:$MODULE\t\t\tMODE=>($MODE)\tINFO=>($INFO)\tCommand1:("$COMMAND1")\tCommand2:("$COMMAND2")"
echo
eval $PRINT_MSG
$READ
if [[ "$input" == "y" ]]
then
	echo -e " #$test_no)\t$MODULE\t\t\tMODE=>($MODE)\tINFO=>($INFO)\tcommand: ("$COMMAND1")\tCommand2: ("$COMMAND2")" >> sanity_log
	echo -e " #$test_no)\tTest case:$MODULE\t\t\tMODE=>($MODE)\tINFO=>($INFO)\tCommand1:("$COMMAND1")\tCommand2:("$COMMAND2")" >> sanity_tested_apps
	append_newline 1
	echo
	echo
	eval "$COMMAND1 >> sanity_log 2>&1 &"
	echo
	sleep 5
	export DPRC=$SDPRC
	eval "$COMMAND2 >> sanity_log 2>&1 &"
	sleep 5
	echo
	ip netns exec sanity_ipsec_ns tcpdump -nt -i $NI3 &
	sleep 20
	append_newline 3
	echo " Starting the ping test ..."
	ping 192.168.222.2 -c $ping_packets | tee log
	RESULT=`grep -o "\w*\.\w*%\|\w*%" log`
	echo
	cat log >> sanity_log
	print_result "$RESULT"
	sleep 2
	killall odp_ipsec
	sleep 6
	ip netns exec sanity_ipsec_ns killall tcpdump
	sleep 5
	append_newline 5
	rm log
	echo
	export DPRC=$FDPRC
	echo
	echo
	echo >> sanity_tested_apps
else
	echo -e " #$test_no)\tTest case:$MODULE\t\t\tMODE=>($MODE)\tINFO=>($INFO)\tCommand1:("$COMMAND1")\tCommand2:("$COMMAND2")" >> sanity_untested_apps
	echo -e "\tNot Tested" | tee -a sanity_untested_apps
	not_tested=`expr $not_tested + 1`
	echo
	echo >> sanity_untested_apps
fi
unset_ipsec_macros
test_no=`expr $test_no + 1`
}

#/* Function to test the odp_ipsec_proto test cases*/

run_ipsec_proto() {
for i in "$@"
do
	arg=$(echo "$i" | grep -o "odp_ipsec_proto")
	if [[ -z $arg ]]
	then
		arg="$i"
	fi
	case $arg in
		-p )
			export ODP_IPSEC_USE_POLL_QUEUES="yes"
			MODE="ODP_IPSEC_USE_POLL_QUEUES"
			;;
		-s )
			MODE="ODP_SCH_PUSH_MODE"
		        ;;
                IPSEC_PROTO )
			MODULE="IPSEC_PROTO"
			;;
		-i=*)
			INFO="${i#*=}"
			;;
		-o )
			INTEROPS=1
			;;
                odp_ipsec_proto )
			if [[ -z $COMMAND1 ]]
			then
				COMMAND1="$i"
			else
				COMMAND2="$i"
			fi
			;;
                *)
		echo -e " #$test_no)\tTest case:$MODULE\t\tMODE=>($MODE)\tINTEROPS=>($INTEROPS)\tINFO=>($INFO)\tCommand1:($COMMAND1)\tCommand2:($COMMAND2)" >> sanity_log
		echo -e " #$test_no)\tTest case:$MODULE\t\tMODE=>($MODE)\tINTEROPS=>($INTEROPS)\tINFO=>($INFO)\tCommand1:($COMMAND1)\tCommand2:($COMMAND2)" >> sanity_untested_apps
		        echo -e "\t$i Invalid Argument" | tee -a sanity_untested_apps
		        echo -e "\t$i Invalid Argument" | tee -a sanity_log
			echo -e "\tNot Tested" | tee -a sanity_untested_apps
			not_tested=`expr $not_tested + 1`
			echo >> sanity_untested_apps
			unset_ipsec_macros
			test_no=`expr $test_no + 1`
			return
		        ;;
	esac
done

if [[ -z $MODE ]]
then
	export ODP_SCH_PULL_MODE=1
	MODE="ODP_SCH_PULL_MODE"
fi


echo -e " #$test_no)\tTest case:$MODULE\t\tMODE=>($MODE)\tINTEROPS=>($INTEROPS)\tINFO=>($INFO)\tCommand1:($COMMAND1)\tCommand2:($COMMAND2)"
echo
eval $PRINT_MSG
$READ
if [[ "$input" == "y" ]]
then
	echo -e " #$test_no)\t$MODULE\t\tMODE=>($MODE)\tINTEROPS=>($INTEROPS)\tINFO=>($INFO)\tCommand1: ($COMMAND1)\tCommand2: ($COMMAND2)" >> sanity_log
	echo -e " #$test_no)\tTest case:$MODULE\t\tMODE=>($MODE)\tINTEROPS=>($INTEROPS)\tINFO=>($INFO)\tCommand1:($COMMAND1)\tCommand2:($COMMAND2)" >> sanity_tested_apps
	append_newline 1
	echo
	echo
	if [[ -z $INTEROPS ]]
	then
		eval "$COMMAND1 >> sanity_log 2>&1 &"
		echo
		sleep 5
		export DPRC=$SDPRC
		eval "$COMMAND2 >> sanity_log 2>&1 &"
		sleep 5
		echo
		ip netns exec sanity_ipsec_ns tcpdump -nt -i $NI3 &
		sleep 20
		append_newline 3
		echo " Starting the ping test ..."
		ping 192.168.222.2 -c $ping_packets | tee log
		RESULT=`grep -o "\w*\.\w*%\|\w*%" log`
		echo
		cat log >> sanity_log
		print_result "$RESULT"
		sleep 2
		killall odp_ipsec_proto
		sleep 6
		ip netns exec sanity_ipsec_ns killall tcpdump
		sleep 5
		append_newline 5
		rm log
		echo
		export DPRC=$FDPRC
		echo
		echo
	else
		cat > ipsec_proto_setkey.sh << EOF
#!/usr/sbin/setkey -f
# Flush the SAD and SPD
flush;
spdflush;

# I am gateway A (eth0:192.168.1.130, eth1:200.200.200.10)
#
# Security policies
spdadd 192.168.111.2 192.168.222.2 any -P in ipsec
	esp/tunnel/192.168.160.1-192.168.160.2/require;

spdadd 192.168.222.2 192.168.111.2 any -P out ipsec
	esp/tunnel/192.168.160.2-192.168.160.1/require;

# ESP SAs doing encryption using 192 bit long keys (168 + 24 parity)
# and hmac-sha1 authentication using 160 bit long keys
add 192.168.160.1 192.168.160.2 esp 0x1 -m tunnel
	-E aes-cbc 0x0102030405060708090a0b0c0d0e0f10
	-A hmac-sha1 0x2122232425262728292a2b2c2d2e2f3031323334;

add 192.168.160.2 192.168.160.1 esp 0x2 -m tunnel
	-E aes-cbc 0x0102030405060708090a0b0c0d0e0f10
	-A hmac-sha1 0x2122232425262728292a2b2c2d2e2f3031323334;
EOF
	chmod 777 ipsec_proto_setkey.sh
	ip netns exec sanity_ns ./ipsec_proto_setkey.sh
	ip netns exec sanity_ipsec_ns ip link set $NI3 netns sanity_ns
	ip netns exec sanity_ns ifconfig $NI2 0.0.0.0 down
	ip netns exec sanity_ns ifconfig $NI2 192.168.160.2
	ip netns exec sanity_ns ifconfig $NI3 192.168.222.2
	ip netns exec sanity_ns ip route add 192.168.111.0/24 via 192.168.160.1
	ip netns exec sanity_ns arp -s 192.168.160.1 000000000503
	sleep 2
	eval "$COMMAND1 >> sanity_log 2>&1 &"
	echo
	sleep 5
	ip netns exec sanity_ns tcpdump -nt -i $NI2 &
	sleep 20
	append_newline 3
	echo " Starting the ping test ..."
	ping 192.168.222.2 -c $ping_packets | tee log
	RESULT=`grep -o "\w*\.\w*%\|\w*%" log`
	echo
	cat log >> sanity_log
	print_result "$RESULT"
	sleep 2
	killall odp_ipsec_proto
	sleep 5
	ip netns exec sanity_ns killall tcpdump
	sleep 5
	ip netns exec sanity_ns setkey -F
	ip netns exec sanity_ns setkey -PF
	rm ipsec_proto_setkey.sh
	rm log
	unconfigure_ethif
	sleep 2
	configure_ethif
	fi
	echo >> sanity_tested_apps
else
	echo -e " #$test_no)\tTest case:$MODULE\t\tMODE=>($MODE)\tINTEROPS=>($INTEROPS)\tINFO=>($INFO)\tCommand1:($COMMAND1)\tCommand2:($COMMAND2)" >> sanity_untested_apps
	echo -e "\tNot Tested" | tee -a sanity_untested_apps
	not_tested=`expr $not_tested + 1`
	echo
	echo >> sanity_untested_apps
fi
unset_ipsec_macros
test_no=`expr $test_no + 1`
}


#/* Function to run the odp_generator test cases*/

run_generator() {
echo -e " #$test_no)\tTest case:$1\t\tCommand:($2) "
echo
eval $PRINT_MSG
$READ
if [[ "$input" == "y" ]]
then
	echo -e " #$test_no)\t$1\t\tcommand ($2) " >> sanity_log
	echo -e " #$test_no)\tTest case:$1\t\tCommand:($2) " >> sanity_tested_apps
	append_newline 1
	echo
	mode=$(echo "$2" | grep -o "\-m\ \w*" | sed 's/-m //')
	if [[ $mode == "p" ]]
	then
		arp -s 192.168.111.1 000000000501
		no_of_packets=$(echo "$2" | grep -o "\-n\ \w*" | sed 's/-n //')
		eval "$2 > generator_log 2>&1 &"
		sleep 40
		killall odp_generator
		sleep 15
		cat generator_log >> sanity_log
		ICMP=`grep -o "ICMP: \w*" generator_log | tail -1`
		grep -r ICMP generator_log
		if [[ $ICMP == "ICMP: $no_of_packets" ]]
		then
			echo -e $GREEN "\t$no_of_packets packets received successfully"$NC
			echo -e "\tNo packet loss  ----- PASSED" >> sanity_tested_apps
			passed=`expr $passed + 1`
		elif [[ $ICMP == "ICMP: 0" ]]
		then
			echo -e $RED "\t$no_of_packets ping request packet sent and received "$ICMP $NC
			echo -e "\t$no_of_packets ping request packet sent and received $ICMP  ----- FAILED" >> sanity_tested_apps
			failed=`expr $failed + 1`
		elif [[ -z $ICMP ]]
		then
			echo -e $RED " Unable to capture Results"$NC
			echo -e "\tunable to capture Results  ----- N/A" >> sanity_tested_apps
			na=`expr $na + 1`
		else
			echo -e $RED "\t$no_of_packets ping request packet sent and received "$ICMP $NC
			echo -e "\t$no_of_packets ping request packet sent and received $ICMP  ----- PARTIAL PASSED" >> sanity_tested_apps
			partial=`expr $partial + 1`
		fi
		echo
	elif [[ $mode == "u" ]]
	then
		tcpdump -i $NI > tcplog &
		sleep 5
		no_of_packets=$(echo "$2" | grep -o "\-n\ \w*" | sed 's/-n //')
		eval "$2 >> sanity_log 2>&1 &"
		sleep 20
		killall odp_generator
		sleep 15
		killall tcpdump
		sleep 2
		RESULTS=`grep -c UDP tcplog`
		if [[ "$RESULTS" == $no_of_packets ]]
		then
			echo -e $GREEN "\tno packet loss"$NC
			echo -e "\tNo packet loss  ----- PASSED" >> sanity_tested_apps
			passed=`expr $passed + 1`
		elif [[ "$RESULTS" == "0" ]]
		then
			echo -e $RED "\tReceived packets $RESULTS"$NC
			echo -e "\t  Received packets $RESULTS----- FAILED" >> sanity_tested_apps
			failed=`expr $failed + 1`
		elif [[ -z "$RESULTS" ]]
		then
			echo -e $RED "\tUnable to capture Results"$NC
			echo -e "\tunable to capture Results  ----- N/A" >> sanity_tested_apps
			na=`expr $na + 1`
		else
			echo -e $RED "\tReceived packets $RESULTS"$NC
			echo -e "\t  Received packets $RESULTS----- PARTIAL PASSED" >> sanity_tested_apps
			partial=`expr $partial + 1`
		fi
		rm tcplog
	elif [[ $mode == "r" ]]
	then
		eval "$2 > generator_log 2>&1 &"
		sleep 10
		iperf -c 192.168.222.2 -u -p 12345 -t 5 > log 2>&1
		sleep 40
		killall odp_generator
		sleep 15
		cat generator_log >> sanity_log
		UDP=`grep -o "UDP: \w*" generator_log | tail -1 | sed 's/UDP: //g'`
		SENT=`grep -o "Sent \w*" log | sed 's/Sent //g'`
		SENT=`expr $SENT + 10`
		grep -r UDP generator_log
		if [[ $SENT == $UDP ]]
		then
			echo -e $GREEN "\t$UDP packets received successfully"$NC
			echo -e "\tNo packet loss  ----- PASSED" >> sanity_tested_apps
			passed=`expr $passed + 1`
		elif [[ $UDP == "0" ]]
		then
			echo -e $RED "\t$SENT packets sent and received "$UDP $NC
			echo -e "\t$SENT packets sent and received $UDP  ----- FAILED" >> sanity_tested_apps
			failed=`expr $failed + 1`
		elif [[ -z $UDP ]]
		then
			echo -e $RED "\tUnable to capture Results"$NC
			echo -e "\tunable to capture Results  ----- N/A" >> sanity_tested_apps
			na=`expr $na + 1`
		else
			echo -e $RED "\t$SENT packets sent and received "$UDP $NC
			echo -e "\t$SENT packets sent and received $UDP  ----- PARTIAL PASSED" >> sanity_tested_apps
			partial=`expr $partial + 1`
		fi
		echo
		rm log
		rm generator_log
	else
		echo -e "\tINVALID MODE"
	fi
	echo
	append_newline 5
	echo
	echo
	echo
	echo >> sanity_tested_apps
else
	echo -e " #$test_no)\tTest case:$1\t\tCommand:($2) " >> sanity_untested_apps
	echo -e "\tNot Tested" | tee -a sanity_untested_apps
	not_tested=`expr $not_tested + 1`
	echo
	echo >> sanity_untested_apps
fi
test_no=`expr $test_no + 1`
}


#/* Function to run the odp_kni_demo test cases*/

run_kni() {
echo -e " #$test_no)\tTest case:$1\t\t\tCommand:($2) "
echo
eval $PRINT_MSG
$READ
if [[ "$input" == "y" ]]
then
	echo -e " #$test_no)\t$1\t\tcommand ($2) " >> sanity_log
	echo -e " #$test_no)\tTest case:$1\t\t\tCommand:($2) " >> sanity_tested_apps
	append_newline 1
	KNI_MODULE=`find /lib -name odpfsl_kni.ko`
	if [[ -z $KNI_MODULE ]]
	then
		echo -e $RED"\tUnable to find odpfsl_kni.ko"$NC
		echo -e "\tUnable to find odpfsl_kni.ko ----- FAILED" >> sanity_tested_apps
		echo >> sanity_tested_apps
		failed=`expr $failed + 1`
		test_no=`expr $test_no + 1`
		return
	fi
	insmod $KNI_MODULE
	sleep 1
	KETH=`echo "$2" | grep  -o "\-i dpni\-\w*" | sed 's/-i dpni/keth/g'`
	echo $KETH
	eval "$2 >> sanity_log 2>&1 &"
	echo
	sleep 3
	append_newline 3
	ip netns add knins
	ip link set $KETH netns knins
	ip netns exec knins ifconfig $KETH 192.168.111.1
	echo " Starting the ping test ..."
	ping 192.168.111.1 -c $ping_packets | tee log
	RESULT=`grep -o "\w*\.\w*%\|\w*%" log`
	echo
	cat log >> sanity_log
	print_result "$RESULT"
	ip netns del knins
	pid=`ps | pgrep kni_demo`
	kill -2 $pid
	sleep 5
	rmmod odpfsl_kni
	sleep 3
	append_newline 5
	rm log
	echo
	echo
	echo
	echo >> sanity_tested_apps
else
	echo -e " #$test_no)\tTest case:$1\t\t\tCommand:($2) " >> sanity_untested_apps
	echo -e "\tNot Tested" | tee -a sanity_untested_apps
	not_tested=`expr $not_tested + 1`
	echo
	echo >> sanity_untested_apps
fi
test_no=`expr $test_no + 1`
}

#/* Function to run the odp_l3fwd test cases*/

run_l3fwd() {
echo -e " #$test_no)\tTest case:$1\t\t\tCommand:($2) "
echo
eval $PRINT_MSG
$READ
if [[ "$input" == "y" ]]
then
	echo -e " #$test_no)\t$1\t\tcommand ($2) " >> sanity_log
	echo -e " #$test_no)\tTest case:$1\t\t\tCommand:($2) " >> sanity_tested_apps
	append_newline 1
	echo
	eval "$2 >> sanity_log 2>&1 &"
	echo
	append_newline 3
	sleep 20
	ip netns exec sanity_ns iperf -s -u -p 12345 &
	sleep 1
	iperf -c 192.168.222.2 -u -p 12345 -t 30 > log
	sleep 1
	cat log >> sanity_log
	cat log
	RESULT=`grep -o "\w*\.\w*%\|\w*%" log`
	print_result "$RESULT"
	echo
	rm log
	append_newline 3
	killall odp_l3fwd
	sleep 5
	killall iperf
	append_newline 5
	sleep 5
	echo
	echo >> sanity_tested_apps
else
	echo -e " #$test_no)\tTest case:$1\t\t\tCommand:($2) " >> sanity_untested_apps
	echo -e "\tNot Tested" | tee -a sanity_untested_apps
	not_tested=`expr $not_tested + 1`
	echo
	echo >> sanity_untested_apps
fi
test_no=`expr $test_no + 1`
}


#/* Common function to run all test cases*/

run_command() {
case $1 in
	PKTIO | REFLECTOR )
		run_pktio $1 "$2"
		;;
	KNI )
		run_kni $1 "$2"
		;;
	TIMER )
		run_timer $1 "$2"
		;;
	L3FWD )
		run_l3fwd $1 "$2"
		;;
	GENERATOR )
		run_generator $1 "$2"
		;;
	CLASSIFIER )
		run_classifier $1 "$2"
		;;
	IPSEC )
		run_ipsec "$@"
		;;
	IPSEC_PROTO )
		run_ipsec_proto "$@"
		;;
	*)
		echo "Invalid test case $1"
esac
}

#function to run odp example applications
run_odp() {
	#/* ODP_PKTIO MODE 0
	# */
	run_command PKTIO "./odp_pktio -c 8 -m 0 -i $FDPNI0"

	#/* ODP_PKTIO MODE 1
	# */
	run_command PKTIO "./odp_pktio -c 8 -m 1 -i $FDPNI0"

	#/* ODP_PKTIO MODE 2
	# */
	run_command PKTIO "./odp_pktio -c 8 -m 2 -i $FDPNI0"

	#/* ODP_REFLECTOR MODE 0
	# */
	run_command REFLECTOR "./odp_reflector -i $FDPNI0 -m 0 -c 8"

	#/* ODP_REFLECTOR MODE 1
	# */
	run_command REFLECTOR "./odp_reflector -i $FDPNI0 -m 1 -c 8"

	#/* ODP_KNI_DEMO
	# */
	run_command KNI "./odp_kni_demo -i $FDPNI0"

	#/* ODP_TIMER_TEST
	# */
	run_command TIMER "./odp_timer_test -c 2 -t 2"

	#/* ODP_TIMER_TEST
	# */
	run_command TIMER "./odp_timer_test -c 2 -t 2 -p 2000000"

	#/* ODP_GENERATOR
	# */
	run_command GENERATOR "./odp_generator -I $FDPNI0 --srcmac 00:00:00:00:05:01  --dstmac 00:00:00:00:08:01 --srcip 192.168.111.1 --dstip 192.168.111.2 -n 10 -m p"

	#/* ODP_GENERATOR
	# */
	run_command GENERATOR "./odp_generator -I $FDPNI0 -m r"

	#/* ODP_GENERATOR
	# */
	run_command GENERATOR "./odp_generator -I $FDPNI0 --srcmac 00:00:00:00:05:01  --dstmac 00:00:00:00:08:01 --srcip 192.168.111.1 --dstip 192.168.111.2 -n 10 -m u"

	#/* ODP_CLASSIFIER
	# */
	run_command CLASSIFIER "./odp_classifier -i $FDPNI0 -p ODP_PMR_SIP_ADDR:192.168.111.2:FFFFFFFF:queue1 -l 2:queue2 -q 40:queue3 -m 1 -a 1"

	#/* ODP_L3FWD
	# */
	run_command L3FWD "./odp_l3fwd -i $FDPNI0,$FDPNI2 -r 192.168.222.0/24:$FDPNI2:00.00.00.00.08.02 -r 192.168.111.0/24:$FDPNI0:00.00.00.00.08.01 -f 1024 -m 0"

	#/* ODP_IPSEC
	# */
	run_command IPSEC "./odp_ipsec -i $FDPNI0,$FDPNI1 -c 8 -m 1 -r 192.168.111.2/32:$FDPNI0:00.00.00.00.08.01 -r 192.168.222.2/32:$FDPNI1:00.00.00.00.06.01 -p 192.168.111.0/24:192.168.222.0/24:out:esp -e 192.168.111.2:192.168.222.2:3des:201:656c8523255ccc23a66c1917aa0cf30991fce83532a4b224 -p 192.168.222.0/24:192.168.111.0/24:in:esp -e 192.168.222.2:192.168.111.2:3des:301:c966199f24d095f3990a320d749056401e82b26570320292" "./odp_ipsec -i $SDPNI0,$SDPNI1 -c 8 -m 1 -r 192.168.111.2/32:$SDPNI0:00.00.00.00.05.02 -r 192.168.222.2/32:$SDPNI1:00.00.00.00.08.03 -p 192.168.111.0/24:192.168.222.0/24:in:esp -e 192.168.111.2:192.168.222.2:3des:201:656c8523255ccc23a66c1917aa0cf30991fce83532a4b224 -p 192.168.222.0/24:192.168.111.0/24:out:esp -e 192.168.222.2:192.168.111.2:3des:301:c966199f24d095f3990a320d749056401e82b26570320292 "

	#/* ODP_IPSEC ( POLL_QUEUE )
	# */
	run_command IPSEC "./odp_ipsec -i $FDPNI0,$FDPNI1 -c 8 -m 1 -r 192.168.111.2/32:$FDPNI0:00.00.00.00.08.01 -r 192.168.222.2/32:$FDPNI1:00.00.00.00.06.01 -p 192.168.111.0/24:192.168.222.0/24:out:esp -e 192.168.111.2:192.168.222.2:3des:201:656c8523255ccc23a66c1917aa0cf30991fce83532a4b224 -p 192.168.222.0/24:192.168.111.0/24:in:esp -e 192.168.222.2:192.168.111.2:3des:301:c966199f24d095f3990a320d749056401e82b26570320292" "./odp_ipsec -i $SDPNI0,$SDPNI1 -c 8 -m 1 -r 192.168.111.2/32:$SDPNI0:00.00.00.00.05.02 -r 192.168.222.2/32:$SDPNI1:00.00.00.00.08.03 -p 192.168.111.0/24:192.168.222.0/24:in:esp -e 192.168.111.2:192.168.222.2:3des:201:656c8523255ccc23a66c1917aa0cf30991fce83532a4b224 -p 192.168.222.0/24:192.168.111.0/24:out:esp -e 192.168.222.2:192.168.111.2:3des:301:c966199f24d095f3990a320d749056401e82b26570320292 " -p

	#/* ODP_IPSEC (SCHED_PUSH)
	# */
	run_command IPSEC "./odp_ipsec -i $FDPNI0,$FDPNI1 -c 8 -m 1 -r 192.168.111.2/32:$FDPNI0:00.00.00.00.08.01 -r 192.168.222.2/32:$FDPNI1:00.00.00.00.06.01 -p 192.168.111.0/24:192.168.222.0/24:out:esp -e 192.168.111.2:192.168.222.2:3des:201:656c8523255ccc23a66c1917aa0cf30991fce83532a4b224 -p 192.168.222.0/24:192.168.111.0/24:in:esp -e 192.168.222.2:192.168.111.2:3des:301:c966199f24d095f3990a320d749056401e82b26570320292" "./odp_ipsec -i $SDPNI0,$SDPNI1 -c 8 -m 1 -r 192.168.111.2/32:$SDPNI0:00.00.00.00.05.02 -r 192.168.222.2/32:$SDPNI1:00.00.00.00.08.03 -p 192.168.111.0/24:192.168.222.0/24:in:esp -e 192.168.111.2:192.168.222.2:3des:201:656c8523255ccc23a66c1917aa0cf30991fce83532a4b224 -p 192.168.222.0/24:192.168.111.0/24:out:esp -e 192.168.222.2:192.168.111.2:3des:301:c966199f24d095f3990a320d749056401e82b26570320292 " -s


	#/* ODP_IPSEC ( SCHED_PULL ) (TUNNEL) (ESP)
	# */
	run_command IPSEC "./odp_ipsec -i $FDPNI0,$FDPNI1 -r 192.168.111.2/32:$FDPNI0:00.00.00.00.08.01 -r 192.168.222.2/32:$FDPNI1:00.00.00.00.06.01 -p 192.168.111.0/24:192.168.222.0/24:out:esp -e 192.168.111.2:192.168.222.2:3des:1:656c8523255ccc23a66c1917aa0cf30991fce83532a4b224 -t 192.168.111.2:192.168.222.2:192.168.160.1:192.168.160.2 -p 192.168.222.0/24:192.168.111.0/24:in:esp -e 192.168.222.2:192.168.111.2:3des:2:c966199f24d095f3990a320d749056401e82b26570320292 -t 192.168.222.2:192.168.111.2:192.168.160.2:192.168.160.1 -c 8 -m 1" "./odp_ipsec -i $SDPNI0,$SDPNI1 -r 192.168.222.2/32:$SDPNI1:00.00.00.00.08.03 -r 192.168.111.2/32:$SDPNI0:00.00.00.00.05.02 -p 192.168.111.0/24:192.168.222.0/24:in:esp -e 192.168.111.2:192.168.222.2:3des:1:656c8523255ccc23a66c1917aa0cf30991fce83532a4b224 -t 192.168.111.2:192.168.222.2:192.168.160.1:192.168.160.2 -p 192.168.222.0/24:192.168.111.0/24:out:esp -e 192.168.222.2:192.168.111.2:3des:2:c966199f24d095f3990a320d749056401e82b26570320292 -t 192.168.222.2:192.168.111.2:192.168.160.2:192.168.160.1 -c 8 -m 1" -i="ALGO: ESP"

	#/* ODP_IPSEC ( POLL_QUEUE ) (TUNNEL)
	# */
	run_command IPSEC "./odp_ipsec -i $FDPNI0,$FDPNI1 -r 192.168.111.2/32:$FDPNI0:00.00.00.00.08.01 -r 192.168.222.2/32:$FDPNI1:00.00.00.00.06.01 -p 192.168.111.0/24:192.168.222.0/24:out:esp -e 192.168.111.2:192.168.222.2:3des:1:656c8523255ccc23a66c1917aa0cf30991fce83532a4b224 -t 192.168.111.2:192.168.222.2:192.168.160.1:192.168.160.2 -p 192.168.222.0/24:192.168.111.0/24:in:esp -e 192.168.222.2:192.168.111.2:3des:2:c966199f24d095f3990a320d749056401e82b26570320292 -t 192.168.222.2:192.168.111.2:192.168.160.2:192.168.160.1 -c 8 -m 1" "./odp_ipsec -i $SDPNI0,$SDPNI1 -r 192.168.222.2/32:$SDPNI1:00.00.00.00.08.03 -r 192.168.111.2/32:$SDPNI0:00.00.00.00.05.02 -p 192.168.111.0/24:192.168.222.0/24:in:esp -e 192.168.111.2:192.168.222.2:3des:1:656c8523255ccc23a66c1917aa0cf30991fce83532a4b224 -t 192.168.111.2:192.168.222.2:192.168.160.1:192.168.160.2 -p 192.168.222.0/24:192.168.111.0/24:out:esp -e 192.168.222.2:192.168.111.2:3des:2:c966199f24d095f3990a320d749056401e82b26570320292 -t 192.168.222.2:192.168.111.2:192.168.160.2:192.168.160.1 -c 8 -m 1" -p -i="ALGO: ESP"

	#/* ODP_IPSEC ( SCHED_PUSH ) (TUNNEL)
	# */
	run_command IPSEC "./odp_ipsec -i $FDPNI0,$FDPNI1 -r 192.168.111.2/32:$FDPNI0:00.00.00.00.08.01 -r 192.168.222.2/32:$FDPNI1:00.00.00.00.06.01 -p 192.168.111.0/24:192.168.222.0/24:out:esp -e 192.168.111.2:192.168.222.2:3des:1:656c8523255ccc23a66c1917aa0cf30991fce83532a4b224 -t 192.168.111.2:192.168.222.2:192.168.160.1:192.168.160.2 -p 192.168.222.0/24:192.168.111.0/24:in:esp -e 192.168.222.2:192.168.111.2:3des:2:c966199f24d095f3990a320d749056401e82b26570320292 -t 192.168.222.2:192.168.111.2:192.168.160.2:192.168.160.1 -c 8 -m 1" "./odp_ipsec -i $SDPNI0,$SDPNI1 -r 192.168.222.2/32:$SDPNI1:00.00.00.00.08.03 -r 192.168.111.2/32:$SDPNI0:00.00.00.00.05.02 -p 192.168.111.0/24:192.168.222.0/24:in:esp -e 192.168.111.2:192.168.222.2:3des:1:656c8523255ccc23a66c1917aa0cf30991fce83532a4b224 -t 192.168.111.2:192.168.222.2:192.168.160.1:192.168.160.2 -p 192.168.222.0/24:192.168.111.0/24:out:esp -e 192.168.222.2:192.168.111.2:3des:2:c966199f24d095f3990a320d749056401e82b26570320292 -t 192.168.222.2:192.168.111.2:192.168.160.2:192.168.160.1 -c 8 -m 1" -s -i="ALGO: ESP"

	#/* ODP_IPSEC ( SCHED_PULL ) (TUNNEL) (AH)
	# */
	run_command IPSEC "./odp_ipsec -i $FDPNI0,$FDPNI1 -r 192.168.111.2/32:$FDPNI0:00.00.00.00.08.01 -r 192.168.222.2/32:$FDPNI1:00.00.00.00.06.01 -p 192.168.111.0/24:192.168.222.0/24:out:ah -a 192.168.111.2:192.168.222.2:md5:1:2122232425262728292a2b2c2d2e2f30 -t 192.168.111.2:192.168.222.2:192.168.160.1:192.168.160.2 -p 192.168.222.0/24:192.168.111.0/24:in:ah -a 192.168.222.2:192.168.111.2:md5:2:2122232425262728292a2b2c2d2e2f30 -t 192.168.222.2:192.168.111.2:192.168.160.2:192.168.160.1 -c 8 -m 1" "./odp_ipsec -i $SDPNI0,$SDPNI1 -r 192.168.222.2/32:$SDPNI1:00.00.00.00.08.03 -r 192.168.111.2/32:$SDPNI0:00.00.00.00.05.02 -p 192.168.111.0/24:192.168.222.0/24:in:ah -a 192.168.111.2:192.168.222.2:md5:1:2122232425262728292a2b2c2d2e2f30 -t 192.168.111.2:192.168.222.2:192.168.160.1:192.168.160.2 -p 192.168.222.0/24:192.168.111.0/24:out:ah -a 192.168.222.2:192.168.111.2:md5:2:2122232425262728292a2b2c2d2e2f30 -t 192.168.222.2:192.168.111.2:192.168.160.2:192.168.160.1 -c 8 -m 1" -i="ALGO: AH"

	#/* ODP_IPSEC ( POLL_QUEUES ) (TUNNEL) (AH)
	# */
	run_command IPSEC "./odp_ipsec -i $FDPNI0,$FDPNI1 -r 192.168.111.2/32:$FDPNI0:00.00.00.00.08.01 -r 192.168.222.2/32:$FDPNI1:00.00.00.00.06.01 -p 192.168.111.0/24:192.168.222.0/24:out:ah -a 192.168.111.2:192.168.222.2:md5:1:2122232425262728292a2b2c2d2e2f30 -t 192.168.111.2:192.168.222.2:192.168.160.1:192.168.160.2 -p 192.168.222.0/24:192.168.111.0/24:in:ah -a 192.168.222.2:192.168.111.2:md5:2:2122232425262728292a2b2c2d2e2f30 -t 192.168.222.2:192.168.111.2:192.168.160.2:192.168.160.1 -c 8 -m 1" "./odp_ipsec -i $SDPNI0,$SDPNI1 -r 192.168.222.2/32:$SDPNI1:00.00.00.00.08.03 -r 192.168.111.2/32:$SDPNI0:00.00.00.00.05.02 -p 192.168.111.0/24:192.168.222.0/24:in:ah -a 192.168.111.2:192.168.222.2:md5:1:2122232425262728292a2b2c2d2e2f30 -t 192.168.111.2:192.168.222.2:192.168.160.1:192.168.160.2 -p 192.168.222.0/24:192.168.111.0/24:out:ah -a 192.168.222.2:192.168.111.2:md5:2:2122232425262728292a2b2c2d2e2f30 -t 192.168.222.2:192.168.111.2:192.168.160.2:192.168.160.1 -c 8 -m 1" -p -i="ALGO: AH"

	#/* ODP_IPSEC ( SCHED_PUSH ) (TUNNEL) (AH)
	# */
	run_command IPSEC "./odp_ipsec -i $FDPNI0,$FDPNI1 -r 192.168.111.2/32:$FDPNI0:00.00.00.00.08.01 -r 192.168.222.2/32:$FDPNI1:00.00.00.00.06.01 -p 192.168.111.0/24:192.168.222.0/24:out:ah -a 192.168.111.2:192.168.222.2:md5:1:2122232425262728292a2b2c2d2e2f30 -t 192.168.111.2:192.168.222.2:192.168.160.1:192.168.160.2 -p 192.168.222.0/24:192.168.111.0/24:in:ah -a 192.168.222.2:192.168.111.2:md5:2:2122232425262728292a2b2c2d2e2f30 -t 192.168.222.2:192.168.111.2:192.168.160.2:192.168.160.1 -c 8 -m 1" "./odp_ipsec -i $SDPNI0,$SDPNI1 -r 192.168.222.2/32:$SDPNI1:00.00.00.00.08.03 -r 192.168.111.2/32:$SDPNI0:00.00.00.00.05.02 -p 192.168.111.0/24:192.168.222.0/24:in:ah -a 192.168.111.2:192.168.222.2:md5:1:2122232425262728292a2b2c2d2e2f30 -t 192.168.111.2:192.168.222.2:192.168.160.1:192.168.160.2 -p 192.168.222.0/24:192.168.111.0/24:out:ah -a 192.168.222.2:192.168.111.2:md5:2:2122232425262728292a2b2c2d2e2f30 -t 192.168.222.2:192.168.111.2:192.168.160.2:192.168.160.1 -c 8 -m 1" -s -i="ALGO: AH"

	#/* ODP_IPSEC ( SCHED_PULL ) (TUNNEL) (AEAD)
	# */
	run_command IPSEC "./odp_ipsec -i $FDPNI0,$FDPNI1 -r 192.168.111.2/32:$FDPNI0:00.00.00.00.08.01 -r 192.168.222.2/32:$FDPNI1:00.00.00.00.06.01 -p 192.168.111.0/24:192.168.222.0/24:out:both -e 192.168.111.2:192.168.222.2:3des:1:0102030405060708090a0b0c0d0e0f101112131415161718 -a 192.168.111.2:192.168.222.2:md5:1:2122232425262728292a2b2c2d2e2f30 -t 192.168.111.2:192.168.222.2:192.168.160.1:192.168.160.2 -p 192.168.222.0/24:192.168.111.0/24:in:both -e 192.168.222.2:192.168.111.2:3des:2:0102030405060708090a0b0c0d0e0f101112131415161718 -a 192.168.222.2:192.168.111.2:md5:2:2122232425262728292a2b2c2d2e2f30 -t 192.168.222.2:192.168.111.2:192.168.160.2:192.168.160.1 -c 8 -m 1" "./odp_ipsec -i $SDPNI0,$SDPNI1 -r 192.168.222.2/32:$SDPNI1:00.00.00.00.08.03 -r 192.168.111.2/32:$SDPNI0:00.00.00.00.05.02 -p 192.168.111.0/24:192.168.222.0/24:in:both -e 192.168.111.2:192.168.222.2:3des:1:0102030405060708090a0b0c0d0e0f101112131415161718 -a 192.168.111.2:192.168.222.2:md5:1:2122232425262728292a2b2c2d2e2f30 -t 192.168.111.2:192.168.222.2:192.168.160.1:192.168.160.2 -p 192.168.222.0/24:192.168.111.0/24:out:both -e 192.168.222.2:192.168.111.2:3des:2:0102030405060708090a0b0c0d0e0f101112131415161718 -a 192.168.222.2:192.168.111.2:md5:2:2122232425262728292a2b2c2d2e2f30 -t 192.168.222.2:192.168.111.2:192.168.160.2:192.168.160.1 -c 8 -m 1" -i="ALGO: AEAD"

	#/* ODP_IPSEC ( POLL_QUEUES ) (TUNNEL) (AEAD)
	# */
	run_command IPSEC "./odp_ipsec -i $FDPNI0,$FDPNI1 -r 192.168.111.2/32:$FDPNI0:00.00.00.00.08.01 -r 192.168.222.2/32:$FDPNI1:00.00.00.00.06.01 -p 192.168.111.0/24:192.168.222.0/24:out:both -e 192.168.111.2:192.168.222.2:3des:1:0102030405060708090a0b0c0d0e0f101112131415161718 -a 192.168.111.2:192.168.222.2:md5:1:2122232425262728292a2b2c2d2e2f30 -t 192.168.111.2:192.168.222.2:192.168.160.1:192.168.160.2 -p 192.168.222.0/24:192.168.111.0/24:in:both -e 192.168.222.2:192.168.111.2:3des:2:0102030405060708090a0b0c0d0e0f101112131415161718 -a 192.168.222.2:192.168.111.2:md5:2:2122232425262728292a2b2c2d2e2f30 -t 192.168.222.2:192.168.111.2:192.168.160.2:192.168.160.1 -c 8 -m 1" "./odp_ipsec -i $SDPNI0,$SDPNI1 -r 192.168.222.2/32:$SDPNI1:00.00.00.00.08.03 -r 192.168.111.2/32:$SDPNI0:00.00.00.00.05.02 -p 192.168.111.0/24:192.168.222.0/24:in:both -e 192.168.111.2:192.168.222.2:3des:1:0102030405060708090a0b0c0d0e0f101112131415161718 -a 192.168.111.2:192.168.222.2:md5:1:2122232425262728292a2b2c2d2e2f30 -t 192.168.111.2:192.168.222.2:192.168.160.1:192.168.160.2 -p 192.168.222.0/24:192.168.111.0/24:out:both -e 192.168.222.2:192.168.111.2:3des:2:0102030405060708090a0b0c0d0e0f101112131415161718 -a 192.168.222.2:192.168.111.2:md5:2:2122232425262728292a2b2c2d2e2f30 -t 192.168.222.2:192.168.111.2:192.168.160.2:192.168.160.1 -c 8 -m 1" -p -i="ALGO: AEAD"

	#/* ODP_IPSEC ( SCHED_PUSH ) (TUNNEL) (AEAD)
	# */
	run_command IPSEC "./odp_ipsec -i $FDPNI0,$FDPNI1 -r 192.168.111.2/32:$FDPNI0:00.00.00.00.08.01 -r 192.168.222.2/32:$FDPNI1:00.00.00.00.06.01 -p 192.168.111.0/24:192.168.222.0/24:out:both -e 192.168.111.2:192.168.222.2:3des:1:0102030405060708090a0b0c0d0e0f101112131415161718 -a 192.168.111.2:192.168.222.2:md5:1:2122232425262728292a2b2c2d2e2f30 -t 192.168.111.2:192.168.222.2:192.168.160.1:192.168.160.2 -p 192.168.222.0/24:192.168.111.0/24:in:both -e 192.168.222.2:192.168.111.2:3des:2:0102030405060708090a0b0c0d0e0f101112131415161718 -a 192.168.222.2:192.168.111.2:md5:2:2122232425262728292a2b2c2d2e2f30 -t 192.168.222.2:192.168.111.2:192.168.160.2:192.168.160.1 -c 8 -m 1" "./odp_ipsec -i $SDPNI0,$SDPNI1 -r 192.168.222.2/32:$SDPNI1:00.00.00.00.08.03 -r 192.168.111.2/32:$SDPNI0:00.00.00.00.05.02 -p 192.168.111.0/24:192.168.222.0/24:in:both -e 192.168.111.2:192.168.222.2:3des:1:0102030405060708090a0b0c0d0e0f101112131415161718 -a 192.168.111.2:192.168.222.2:md5:1:2122232425262728292a2b2c2d2e2f30 -t 192.168.111.2:192.168.222.2:192.168.160.1:192.168.160.2 -p 192.168.222.0/24:192.168.111.0/24:out:both -e 192.168.222.2:192.168.111.2:3des:2:0102030405060708090a0b0c0d0e0f101112131415161718 -a 192.168.222.2:192.168.111.2:md5:2:2122232425262728292a2b2c2d2e2f30 -t 192.168.222.2:192.168.111.2:192.168.160.2:192.168.160.1 -c 8 -m 1" -s -i="ALGO: AEAD"

	#/* ODP_IPSEC_PROTO ( POLL_QUEUE ) (TUNNEL)
	# */
	run_command IPSEC_PROTO "./odp_ipsec_proto -i $FDPNI0,$FDPNI1 -r 192.168.111.2/32:$FDPNI0:00.00.00.00.08.01 -r 192.168.222.2/32:$FDPNI1:00.00.00.00.06.01 -p 192.168.111.0/24:192.168.222.0/24:out:both -e 192.168.111.2:192.168.222.2:aes:1:0102030405060708090a0b0c0d0e0f10 -a 192.168.111.2:192.168.222.2:hmac:1:2122232425262728292a2b2c2d2e2f3031323334 -t 192.168.111.2:192.168.222.2:192.168.160.1:192.168.160.2 -p 192.168.222.0/24:192.168.111.0/24:in:both -e 192.168.222.2:192.168.111.2:aes:2:0102030405060708090a0b0c0d0e0f10 -a 192.168.222.2:192.168.111.2:hmac:2:2122232425262728292a2b2c2d2e2f3031323334 -t 192.168.222.2:192.168.111.2:192.168.160.2:192.168.160.1 -c 8 -m 1" "./odp_ipsec_proto -i $SDPNI0,$SDPNI1 -r 192.168.222.2/32:$SDPNI1:00.00.00.00.08.03 -r 192.168.111.2/32:$SDPNI0:00.00.00.00.05.02 -p 192.168.111.0/24:192.168.222.0/24:in:both -e 192.168.111.2:192.168.222.2:aes:1:0102030405060708090a0b0c0d0e0f10 -a 192.168.111.2:192.168.222.2:hmac:1:2122232425262728292a2b2c2d2e2f3031323334 -t 192.168.111.2:192.168.222.2:192.168.160.1:192.168.160.2 -p 192.168.222.0/24:192.168.111.0/24:out:both -e 192.168.222.2:192.168.111.2:aes:2:0102030405060708090a0b0c0d0e0f10 -a 192.168.222.2:192.168.111.2:hmac:2:2122232425262728292a2b2c2d2e2f3031323334 -t 192.168.222.2:192.168.111.2:192.168.160.2:192.168.160.1 -c 8 -m 1" -p

	#/* ODP_IPSEC_PROTO ( POLL_QUEUE ) (TUNNEL) (INTEROPS)
	# */
	run_command IPSEC_PROTO "./odp_ipsec_proto -i $FDPNI0,$FDPNI2 -r 192.168.111.2/32:$FDPNI0:00.00.00.00.08.01 -r 192.168.222.2/32:$FDPNI2:00.00.00.00.08.02 -p 192.168.111.0/24:192.168.222.0/24:out:both -e 192.168.111.2:192.168.222.2:aes:1:0102030405060708090a0b0c0d0e0f10 -a 192.168.111.2:192.168.222.2:hmac:1:2122232425262728292a2b2c2d2e2f3031323334 -t 192.168.111.2:192.168.222.2:192.168.160.1:192.168.160.2 -p 192.168.222.0/24:192.168.111.0/24:in:both -e 192.168.222.2:192.168.111.2:aes:2:0102030405060708090a0b0c0d0e0f10 -a 192.168.222.2:192.168.111.2:hmac:2:2122232425262728292a2b2c2d2e2f3031323334 -t 192.168.222.2:192.168.111.2:192.168.160.2:192.168.160.1 -c 8 -m 1" -o
}

run_cunit_command() {
	MODULE=`echo "$1" | grep -o "\w*_\w*"| sed -e 's/_main//g'`
	echo -e " #$cunit_test_no)\tTest case:$MODULE\t\tCommand:($1)"
	echo
	eval $PRINT_MSG
	$READ
	echo
	if [[ "$input" == "y" ]]
	then
		echo -e " #$cunit_test_no)\tTest case:$MODULE\t\tCommand:($1)" >> cunit_log
		if [[ ! -e "$1" ]]
		then
			echo -e " #$cunit_test_no)\tTest case:$MODULE\t\tCommand:($1)" >> cunit_untested_app
			echo -e "\t$1 File doesn't exist" | tee -a cunit_log
			echo -e $RED"\tNot tested"$NC
			echo -e "\t[NT] Not tested" >> cunit_untested_app
			cunit_untested=`expr $cunit_untested + 1`
			cunit_test_no=`expr $cunit_test_no + 1`
			echo >> cunit_untested_app
			echo >> cunit_untested_app
			echo >> cunit_log
			echo >> cunit_log
			echo
			echo
			return;
		fi
		if [[ "$1" == "./pktio_main" ]]
		then
			export ODP_PKTIO_IF0=$SDPNI2
		fi
		eval "$1 > log 2>&1 &"
		sleep 10
		killall $1 > /dev/null 2>&1
		echo
		echo -e " #$cunit_test_no)\tTest case:$MODULE\t\tCommand:($1)" >> cunit_tested_app
		echo >> cunit_tested_app
		sed -n '/^Run Summary/,/^Elapsed/p' log | tee temp_log
		suite_failed_no=`awk '{$2=$2};1' temp_log | cut -f5 -d ' ' | tr -s '\n' ' ' |  cut -f2 -d ' '`
		test_failed_no=`awk '{$2=$2};1' temp_log | cut -f5 -d ' ' | tr -s '\n' ' ' |  cut -f3 -d ' '`
		echo >> cunit_tested_app
		if [[ (! $suite_failed_no) && (! $test_failed_no) ]]
		then
			echo -e "\t[UR] Unknown result" >> cunit_tested_app
			echo -e $RED"\tUnknown result " $NC
			cunit_na=`expr $cunit_na + 1`
		elif [[ $suite_failed_no != 0 || $test_failed_no != 0 ]]
		then
			if [[ $test_failed_no != 0 ]]
			then
				echo -e "\t[FAILED] Number of FAILED tests = "$test_failed_no >> cunit_tested_app
				echo -e $RED"\tNumber of FAILED tests= "$test_failed_no $NC
			else
				echo -e "\t[FAILED] Number of FAILED suites = "$suite_failed_no >> cunit_tested_app
				echo -e $RED"\tNumber of FAILED suites = "$suite_failed_no $NC
			fi
			cunit_failed=`expr $cunit_failed + 1`
		else
			echo -e "\t[PASSED] CUNIT test module '$MODULE' is PASSED " >> cunit_tested_app
			echo -e $GREEN"\tCUNIT test module '$MODULE' is PASSED " $NC
			cunit_passed=`expr $cunit_passed + 1`
		fi

		echo >> cunit_tested_app
		echo >> cunit_tested_app
		cat log >> cunit_log
		echo >> cunit_log
		echo >> cunit_log
		echo
		echo
		rm log
		rm temp_log
	else
		echo -e " #$cunit_test_no)\tTest case:$MODULE\t\tCommand:($1)" >> cunit_untested_app
		echo -e "\tNot tested" >> cunit_untested_app
		echo -e $RED"\tNot tested" $NC
		cunit_untested=`expr $cunit_untested + 1`
		echo >> cunit_untested_app
		echo >> cunit_untested_app
		echo
		echo
	fi
	cunit_test_no=`expr $cunit_test_no + 1`
}


#function to run CUNIT
run_cunit() {
	run_cunit_command "./init_main_ok"
	run_cunit_command "./init_main_log"
	run_cunit_command "./init_main_abort"
	run_cunit_command "./config_main"
	run_cunit_command "./queue_main"
	run_cunit_command "./buffer_main"
	run_cunit_command "./classification_main"
	run_cunit_command "./cpumask_main"
	run_cunit_command "./crypto_main"
	run_cunit_command "./proto_main"
	run_cunit_command "./errno_main"
	run_cunit_command "./packet_main"
	run_cunit_command "./pktio_main"
	run_cunit_command "./pool_main"
	run_cunit_command "./random_main"
	run_cunit_command "./scheduler_main"
	run_cunit_command "./shmem_main"
	run_cunit_command "./synchronizers_main"
	run_cunit_command "./system_main"
	run_cunit_command "./thread_main"
	run_cunit_command "./time_main"
	run_cunit_command "./timer_main"
}

#/* configuring the interfaces*/

configure_ethif() {
	ifconfig $NI 192.168.111.2
	ifconfig $NI hw ether 00:00:00:00:08:01
	ip route add 192.168.222.0/24 via 192.168.111.1
	arp -s 192.168.111.1 000000000501
	ip netns add sanity_ns
	ip link set $NI2 netns sanity_ns
	ip netns exec sanity_ns ifconfig $NI2 192.168.222.2
	ip netns exec sanity_ns ifconfig $NI2 hw ether 00:00:00:00:08:02
	ip netns exec sanity_ns ip route add 192.168.111.0/24 via 192.168.222.1
	ip netns exec sanity_ns arp -s 192.168.222.1 000000000503
	ip netns add sanity_ipsec_ns
	ip link set $NI3 netns sanity_ipsec_ns
	ip netns exec sanity_ipsec_ns ifconfig $NI3 192.168.222.2
	ip netns exec sanity_ipsec_ns ifconfig $NI3 hw ether 00:00:00:00:08:03
	ip netns exec sanity_ipsec_ns ip route add 192.168.111.0/24 via 192.168.222.1
	ip netns exec sanity_ipsec_ns arp -s 192.168.222.1 000000000502
	cd /usr/odp/bin/
	echo
	echo
	echo
}

unconfigure_ethif() {
	ip netns del sanity_ipsec_ns
	ip netns del sanity_ns
	ifconfig $NI down
	cd -
}

main() {
	if [[ ! ($CUNIT == 1 && $input != y) ]]
	then
		export DPRC=$FDPRC
		echo "############################################## TEST CASES ###############################################" >> sanity_tested_apps
		echo >> sanity_tested_apps
		run_odp
	fi
	eval $CUNIT_MSG
	$READ_CUNIT_INPUT
	eval $CUNIT_AUTO_MSG
	$READ_CUNIT_AUTO_INPUT
	echo
	if [[ $CUNIT_INPUT == y ]]
	then
		#once the issue QODP-705 resolved change this to PUSH mode.
		export ODP_SCH_PULL_MODE=1
		cd - > /dev/null
		cd /run
		if [[ $CUNIT_AUTO_INPUT != y ]]
		then
			PRINT_MSG="echo -e \"\tEnter 'y' to execute the test case\""
			READ="read input"
		else
			PRINT_MSG=
			READ=
			input=y
		fi
		export DPRC=$SDPRC
		run_cunit
		unset ODP_SCH_PULL_MODE
	else
		SHOW_ONLY_EXAMPLE_OUTPUT=1
	fi

	echo "############################################## TEST REPORT ################################################" >> result
	echo >> result
	echo >> result
	if [[ ! $SHOW_ONLY_CUNIT_OUTPUT ]]
	then
		echo -e "\tODP EXAMPLE APPLICATIONS:" >> result
		echo >> result
		echo -e "\tNo. of passed ODP examples test cases                \t\t= $passed" >> result
		echo -e "\tNo. of failed ODP examples test cases                \t\t= $failed" >> result
		echo -e "\tNo. of partial passed ODP examples test cases        \t\t= $partial" >> result
		echo -e "\tNo. of ODP examples test cases with unknown results  \t\t= $na" >> result
		echo -e "\tNo. of untested ODP examples test cases              \t\t= $not_tested" >> result
		echo -e "\tTotal number of ODP example test cases	              \t\t= `expr $test_no - 1`" >> result
		echo >> result
		mv /usr/odp/bin/sanity_log /usr/odp/scripts/sanity_log
		mv /usr/odp/bin/sanity_tested_apps /usr/odp/scripts/sanity_tested_apps
		if [[ -e "/usr/odp/bin/sanity_untested_apps " ]]
		then
			mv /usr/odp/bin/sanity_untested_apps /usr/odp/scripts/sanity_untested_apps
		fi
	fi
	if [[ ! $SHOW_ONLY_EXAMPLE_OUTPUT ]]
	then
		echo -e "\tCUNIT:" >> result
		echo >> result
		echo -e "\tNo. of passed CUNIT test modules		\t\t= $cunit_passed" >> result
		echo -e "\tNo. of failed CUNIT test modules		\t\t= $cunit_failed" >> result
		echo -e "\tNo. of untested CUNIT test modules		\t\t= $cunit_untested" >> result
		echo -e "\tNo. of CUNIT test modules with unknown results	\t\t= $cunit_na" >> result
		echo -e "\tTotal number CUNIT test modules			\t\t= `expr $cunit_test_no - 1`" >> result
		echo >> result
		mv /run/cunit_log /usr/odp/scripts/cunit_log
		echo >> /usr/odp/scripts/sanity_log
		echo "#################################################### CUNIT ##############################################" >> /usr/odp/scripts/sanity_log
		echo >> /usr/odp/scripts/sanity_log
		cat /usr/odp/scripts/cunit_log >> /usr/odp/scripts/sanity_log
		rm /usr/odp/scripts/cunit_log
		if [[ -e "/run/cunit_tested_app" ]]
		then
			mv /run/cunit_tested_app /usr/odp/scripts/cunit_tested_app
			echo >> /usr/odp/scripts/sanity_tested_apps
			echo "#################################################### CUNIT ##############################################" >> /usr/odp/scripts/sanity_tested_apps
			echo >> /usr/odp/scripts/sanity_tested_apps
			cat /usr/odp/scripts/cunit_tested_app >> /usr/odp/scripts/sanity_tested_apps
			rm /usr/odp/scripts/cunit_tested_app
		fi
		if [[ -e "/run/cunit_untested_app" ]]
		then
			mv /run/cunit_untested_app /usr/odp/scripts/cunit_untested_app
			echo >> /usr/odp/scripts/sanity_untested_apps
			echo "#################################################### CUNIT ##############################################" >> /usr/odp/scripts/sanity_untested_apps
			echo >> /usr/odp/scripts/sanity_untested_apps
			cat /usr/odp/scripts/cunit_untested_app >> /usr/odp/scripts/sanity_untested_apps
			rm /usr/odp/scripts/cunit_untested_app
		fi
	fi
	if [[ (! $SHOW_ONLY_CUNIT_OUTPUT) && (! $SHOW_ONLY_EXAMPLE_OUTPUT) ]]
	then
		echo -e "\tTotal number test cases		                \t\t= `expr $cunit_test_no + $test_no - 2`" >> result
		echo >> sanity_tested_apps
	fi
	echo
	cat result
	echo
	echo >> result
	echo -e "NOTE:  Test results are based on applications logs, If there is change in any application log, results may go wrong.
\tSo it is always better to see console log and sanity_log to verify the results." >> result
	echo >> result
	cat result > /usr/odp/scripts/sanity_test_report
	rm result
	echo
	echo
	echo -e " COMPLETE LOG			=> $GREEN/usr/odp/scripts/sanity_log $NC"
	echo
	echo -e " SANITY TESTED APPS REPORT	=> "$GREEN"/usr/odp/scripts/sanity_tested_apps"$NC
	echo
	echo -e " SANITY UNTESTED APPS		=> "$GREEN"/usr/odp/scripts/sanity_untested_apps"$NC
	echo
	echo -e " SANITY REPORT			=> "$GREEN"/usr/odp/scripts/sanity_test_report"$NC
	echo
	echo " Sanity testing is Done."
	echo
}


# script's starting point
set -m
test_no=1
ping_packets=10
not_tested=0
passed=0
failed=0
partial=0
na=0
input=
cunit_test_no=1
cunit_passed=0
cunit_failed=0
cunit_na=0
cunit_untested=0
CUNIT=0

#/*
# * Parsing the arguments.
# */
if [[ -z "$1" ]]
then
	PRINT_MSG="echo -e \"\tEnter 'y' to execute the test case\""
	READ="read input"
else
	for i in "$@"
	do
		case $i in
			-h)
				help
				[[ "${BASH_SOURCE[0]}" != $0 ]] && return || exit
				;;
			-d)
				developer_help
				[[ "${BASH_SOURCE[0]}" != $0 ]] && return || exit
				;;
			-p=*)
				ping_packets="${i#*=}"
				;;
			-a)
				PRINT_MSG=
				READ=
				input=y
				;;
			-c)
				CUNIT=1
				;;
			*)
				echo "Invalid option $i"
				help
				[[ "${BASH_SOURCE[0]}" != $0 ]] && return || exit
				;;
		esac
	done
fi

if [[ -e "/usr/odp/scripts/sanity_log" ]]
then
	rm /usr/odp/scripts/sanity_log
fi

if [[ -e "/usr/odp/scripts/sanity_tested_apps" ]]
then
	rm /usr/odp/scripts/sanity_tested_apps
fi

if [[ -e "/usr/odp/scripts/sanity_untested_apps" ]]
then
	rm /usr/odp/scripts/sanity_untested_apps
fi

if [[ -e "/usr/odp/scripts/sanity_test_report" ]]
then
	rm /usr/odp/scripts/sanity_test_report
fi

#Handling cunit testing
CUNIT_AUTO_MSG=
CUNIT_AUTO_INPUT=
CUNIT_MSG=
CUNIT_INPUT=
READ_CUNIT_INPUT=
READ_CUNIT_AUTO_INPUT=
SHOW_ONLY_CUNIT_OUTPUT=
SHOW_ONLY_EXAMPLE_OUTPUT=

if [[ $CUNIT == 1 && $input == y ]]
then
	CUNIT_AUTO_INPUT=y
	CUNIT_INPUT=y
elif [[ $CUNIT == 1 ]]
then
	SHOW_ONLY_CUNIT_OUTPUT=1
	CUNIT_AUTO_MSG="echo -e \"Do you want to run all CUNIT applications automatically? (y/n)\""
	READ_CUNIT_AUTO_INPUT="read CUNIT_AUTO_INPUT"
	CUNIT_INPUT=y
elif [[ $input == y ]]
then
	CUNIT_MSG="echo -e \"Do you want to run the CUNIT applications also? (y/n)\""
	READ_CUNIT_INPUT="read CUNIT_INPUT"
	CUNIT_AUTO_INPUT=y
else
	CUNIT_MSG="echo -e \"Do you want to run the CUNIT applications also? (y/n)\""
	READ_CUNIT_INPUT="read CUNIT_INPUT"
fi


#/* Variables represent colors */
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

check_resources
RET=$?
if [[ $RET == 1 ]]
then
	get_resources
fi
configure_ethif
main
unconfigure_ethif
set +m
