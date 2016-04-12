#/*
# * Copyright (c) 2014-2015 Freescale Semiconductor, Inc. All rights reserved.
# *
# *
# */
cat > script_help << EOF


script help :----->

	Run this script as
	". ./dynamic_dpl.sh dpmac.1 dpmac.2 -b ab:cd:ef:gh:ij:kl dpni-dpni dpni-self..."

	Acceptable arguments are dpni-dpni, dpni-self, dpmac.x and -b

    -b [optional] = Specify the MAC base address and must be followed by
		    a valid MAC base address. If this option is there in
		    command line then MAC addresses to DPNIs will be given as:

		    Base address = ab:cd:ef:gh:ij:kl
				 + 00:00:00:00:00:0I
		                  -------------------
				   Actual MAC address

		    where I is the index of the argument

	dpni-dpni = This specify that 2 DPNIs object will be created,
		    which will be connected back to back.
		    dpni.x <-------connected----->dpni.y

		    If -b option is not given then MAC addresses will be like:

		    dpni.x = 00:00:00:00:02:I
		    dpni.y = 00:00:00:00:03:I
		    where I is the index of the argument "dpni-dpni".

	dpni-self = This specify that 1 DPNI object will be created,
		    which will be connected to itself.
		    dpni.x <-------connected----->dpni.x

		    If -b option is not given then MAC address will be as:

		    dpni.x = 00:00:00:00:04:I
		    where I is the index of the argument "dpni-self".

	     dpni = This specify that 1 DPNI object will be created,
		    which will be unconnect.
		    dpni.x ------------- UNCONNECTED

		    If -b option is not given then MAC address will be as:

		    dpni.x = 00:00:00:00:05:I
		    where I is the index of the argument "dpni".

	   dpni.x = This specify that 1 DPNI (dpni.y) object will be created,
		    which will be connected to dpni.x
		    dpni.y <-------connected----->dpni.x

		    If -b option is not given then MAC address will be as:

		    dpni.y = 00:00:00:00:06:I
		    where I is the index of the argument "dpni.y".

	  dpmac.x = This specify that 1 DPNI  (dpni.y) object will be created,
		    which will be connected to dpmac.x.
		    dpmac.x <-------connected----->dpni.y

		    If -b option is not given then MAC address will be as:

		    dpni.y = 00:00:00:00:00:x
		    where x is the ID of the dpmac.x

	This script will create 4 DPBP, 10 DPIOs, 10 DPCIs, 1 DPCON, 1 DPSEC
	and DPNIs depend upon the arguments given during command line.

EOF

#/* getting the objects parameters values from the "ENVIRONMENT VARIABLES"
#/* **DPNI**:-->
#/* MAX_SENDERS		= max number of different senders
#/* MAX_TCS		= maximum traffic classes
#/* MAX_DIST_PER_TC	= maximum distribution'size per RX traffic class
#/* DPNI_OPTIONS	= DPNI related options must be like "DPNI_OPT_MULTICAST_FILTER,DPNI_OPT_UNICAST_FILTER,DPNI_OPT_DIST_HASH" string.
#/* MAX_DIST_KEY_SIZE	= maximum distribution key size
#/*
#/* **DPCON**:-->
#/* DPCON_PRIORITIES	= Number of priorities 1-8
#/*
#/* **DPSECI**:-->
#/* DPSECI_QUEUES	= Number of rx/tx queues
#/* DPSECI_PRIORITIES	= num-queues priorities that can be individually set like "2,2,2.."
#/*
#/* **DPIO**:-->
#/* DPIO_PRIORITIES	= defines priority from 1-8
#/*
#/*
#*/


#/* Function, to intialize the DPNI related parameters
#*/
get_dpni_parameters() {
	if [[ -z "$MAX_SENDERS" ]]
	then
		MAX_SENDERS=8
	fi
	if [[ -z "$MAX_TCS" ]]
	then
		MAX_TCS=1
	fi
	if [[ -z "$MAX_DIST_PER_TC" ]]
	then
		MAX_DIST_PER_TC=8
	fi
	if [[ -z "$DPNI_OPTIONS" ]]
	then
		DPNI_OPTIONS="DPNI_OPT_MULTICAST_FILTER,DPNI_OPT_UNICAST_FILTER,DPNI_OPT_DIST_HASH,DPNI_OPT_DIST_FS,DPNI_OPT_FS_MASK_SUPPORT"
	fi
	if [[ -z "$MAX_DIST_KEY_SIZE" ]]
	then
		MAX_DIST_KEY_SIZE=32
	fi
	echo
	echo  "DPNI parameters :-->"
	echo -e "\tMAX_SENDERS = "$MAX_SENDERS
	echo -e "\tMAX_TCS = "$MAX_TCS
	echo -e "\tMAX_DIST_PER_TC = "$MAX_DIST_PER_TC
	echo -e "\tMAX_DIST_KEY_SIZE = "$MAX_DIST_KEY_SIZE
	echo -e "\tDPNI_OPTIONS = "$DPNI_OPTIONS
	echo
	echo

}

#/* Function, to intialize the DPCON related parameters
#*/
get_dpcon_parameters() {
	if [[ -z "$DPCON_PRIORITIES" ]]
	then
		DPCON_PRIORITIES=8
	fi
	echo "DPCON parameters :-->"
	echo -e "\tDPCON_PRIORITIES = "$DPCON_PRIORITIES
	echo
	echo
}

#/* Function, to intialize the DPSECI related parameters
#*/
get_dpseci_parameters() {
	if [[ -z "$DPSECI_QUEUES" ]]
	then
		DPSECI_QUEUES=8
	fi
	if [[ -z "$DPSECI_PRIORITIES" ]]
	then
		DPSECI_PRIORITIES="2,2,2,2,2,2,2,2"
	fi
	echo "DPSECI parameters :-->"
	echo -e "\tDPSECI_QUEUES = "$DPSECI_QUEUES
	echo -e "\tDPSECI_PRIORITIES = "$DPSECI_PRIORITIES
	echo
	echo
}

#/* Function, to intialize the DPCIO related parameters
#*/
get_dpio_parameters() {
	if [[ -z "$DPIO_PRIORITIES" ]]
	then
		DPIO_PRIORITIES=8
	fi
	echo "DPIO parameters :-->"
	echo -e "\tDPIO_PRIORITIES = "$DPIO_PRIORITIES
}

#/* function, to create the actual MAC address from the base address
#*/
create_actual_mac() {
	last_octet=$(echo $2 | head -1 | cut -f6 -d ':')
	last_octet=$(printf "%d" 0x$last_octet)
	last_octet=$(expr $last_octet + $1)
	last_octet=$(printf "%0.2x" $last_octet)
	if [[ 0x$last_octet -gt 0xFF ]]
        then
		last_octet=$(printf "%d" 0x$last_octet)
		last_octet=`expr $last_octet - 255`
		last_octet=$(printf "%0.2x" $last_octet)
	fi
	ACTUAL_MAC=$(echo $2 | sed -e 's/..$/'$last_octet'/g')
}


#/* script's actual starting point
#*/
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'
if [[ $1 ]]
then
	echo "Available DPRCs"
	restool dprc list

	echo
	#/* Creation of DPRC*/
	export DPRC=$(restool dprc create dprc.1 --label="ODP's container" --options=DPRC_CFG_OPT_SPAWN_ALLOWED,DPRC_CFG_OPT_ALLOC_ALLOWED | head -1 | cut -f1 -d ' ')

	DPRC_LOC=/sys/bus/fsl-mc/devices/$DPRC
	echo $DPRC "Created"

	#/*Validating the arguments*/
	echo
	echo "Validating the arguments....."
	num=1
	max=`expr $# + 1`
	while [[ $num != $max ]]
	do
		if [[ ${!num} == "-b" ]]
		then
			num=`expr $num + 1`
			BASE_ADDR=$(echo ${!num} | egrep "^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")
			if [[ $BASE_ADDR ]]
			then
				echo
				echo -e '\t'$BASE_ADDR" will be used as MAC's base address"
				num=`expr $num + 1`
			else
				echo
				echo -e $RED"\tInvalid MAC base address"$NC
				echo
				restool dprc destroy $DPRC
				echo
				[[ "${BASH_SOURCE[0]}" != $0 ]] && return || exit
			fi
			continue;
		fi
		TYPE=$(echo ${!num} | head -1 | cut -f1 -d '.')
		if [[ ${!num} != "dpni-dpni" && ${!num} != "dpni-self" && $TYPE != "dpmac" && $TYPE != "dpni" ]]
		then
			echo
			echo -e $RED"\tInvalid Argument \""${!num}"\"" $NC
			echo
			restool dprc destroy $DPRC
			cat script_help
			rm script_help
			echo
			[[ "${BASH_SOURCE[0]}" != $0 ]] && return || exit
		fi
		num=`expr $num + 1`
	done

	#/* Getting parameters*/
	get_dpni_parameters
	get_dpcon_parameters
	get_dpseci_parameters
	get_dpio_parameters

	#/* Objects creation*/
	num=1
	max=`expr $# + 1`
	while [[ $num != $max ]]
	do
		echo
		echo
		echo "####### Parsing argument number "$num" ("${!num}") #######"
		echo
		MAC_OCTET2=0
		TYPE=$(echo ${!num} | head -1 | cut -f1 -d '.')
		if [[ ${!num} == "dpni-dpni" ]]
		then
			if [[ $BASE_ADDR ]]
			then
				mac_no=`expr $# + $num`
				create_actual_mac $mac_no $BASE_ADDR
			else
				ACTUAL_MAC="00:00:00:00:02:"$num
			fi
			OBJ=$(restool dpni create --mac-addr=$ACTUAL_MAC --max-senders=$MAX_SENDERS --options=$DPNI_OPTIONS --max-tcs=$MAX_TCS --max-dist-per-tc=$MAX_DIST_PER_TC --max-dist-key-size=$MAX_DIST_KEY_SIZE | head -1 | cut -f1 -d ' ')
			echo $OBJ "created with MAC addr = "$ACTUAL_MAC
			MAC_ADDR1=$ACTUAL_MAC
			MAC_OCTET2=3
			MAC_OCTET1=$num
		elif [[ ${!num} == "dpni-self" ]]
		then
			MAC_OCTET2=4
			MAC_OCTET1=$num;
		elif [[ ${!num} == "dpni" ]]
		then
			MAC_OCTET2=5
			MAC_OCTET1=$num;
		elif [[ $TYPE == "dpni" ]]
		then
			MAC_OCTET2=6
			MAC_OCTET1=$num;
		else
			OBJ=${!num}
			MAC_OCTET1=$(echo $OBJ | head -1 | cut -f2 -d '.');
		fi
		if [[ $BASE_ADDR ]]
		then
			create_actual_mac $num $BASE_ADDR
		else
			ACTUAL_MAC="00:00:00:00:"$MAC_OCTET2":"$MAC_OCTET1
		fi
		DPNI=$(restool dpni create --mac-addr=$ACTUAL_MAC --max-senders=$MAX_SENDERS --options=$DPNI_OPTIONS --max-tcs=$MAX_TCS --max-dist-per-tc=$MAX_DIST_PER_TC --max-dist-key-size=$MAX_DIST_KEY_SIZE | head -1 | cut -f1 -d ' ')
		echo -e '\t'$DPNI "created with MAC addr = "$ACTUAL_MAC
		export DPNI$num=$DPNI
		MAC_ADDR2=$ACTUAL_MAC
		if [[ $TYPE == "dpmac" ]]
		then
			echo -e "\tDisconnecting the" $OBJ", if already connected"
			TEMP=$(restool dprc disconnect dprc.1 --endpoint=$OBJ > /dev/null 2>&1)
			TEMP=$(restool dprc connect dprc.1 --endpoint1=$DPNI --endpoint2=$OBJ 2>&1)
			CHECK=$(echo $TEMP | head -1 | cut -f2 -d ' ');
			if [[ $CHECK == "error:" ]]
			then
				echo -e "\tGetting error, trying to create the "$OBJ
				OBJ_ID=$(echo $OBJ | head -1 | cut -f2 -d '.')
				TEMP=$(restool dpmac create --mac-id=$OBJ_ID 2>&1)
				CHECK=$(echo $TEMP | head -1 | cut -f2 -d ' ');
				if [[ $CHECK == "error:" ]]
				then
					echo -e $RED"\tERROR: unable to create "$OBJ $NC
					echo -e "\tDestroying container "$DPRC
					./destroy_dynamic_dpl.sh $DPRC
					echo
					rm script_help
					[[ "${BASH_SOURCE[0]}" != $0 ]] && return || exit
				fi
				restool dprc connect dprc.1 --endpoint1=$DPNI --endpoint2=$OBJ
			fi
			MAC_ADDR1=
			echo -e '\t'$OBJ" Linked with "$DPNI
			restool dprc sync
			TEMP=$(restool dprc assign dprc.1 --object=$DPNI --child=$DPRC --plugged=1)
			echo -e '\t'$DPNI "assigned to " $DPRC
		elif [[ ${!num} == "dpni" ]]
		then
			restool dprc sync
			TEMP=$(restool dprc assign dprc.1 --object=$DPNI --child=$DPRC --plugged=1)
			echo -e '\t'$DPNI "assigned to " $DPRC
			MAC_ADDR1=
			OBJ=
		elif [[ $TYPE == "dpni" ]]
		then
			echo " printing the dpni ="${!num}
			TEMP=$(restool dprc connect dprc.1 --endpoint1=$DPNI --endpoint2=${!num})
			echo -e '\t'$DPNI" Linked with "${!num}
			restool dprc sync
			TEMP=$(restool dprc assign dprc.1 --object=$DPNI --child=$DPRC --plugged=1)
			echo -e '\t'$DPNI "assigned to " $DPRC
			MAC_ADDR1=N/A
			OBJ=${!num}
		elif [[ ${!num} == "dpni-self" ]]
		then
			TEMP=$(restool dprc connect dprc.1 --endpoint1=$DPNI --endpoint2=$DPNI)
			echo -e '\t'$DPNI" Linked with "$DPNI
			restool dprc sync
			TEMP=$(restool dprc assign dprc.1 --object=$DPNI --child=$DPRC --plugged=1)
			echo -e '\t'$DPNI "assigned to " $DPRC
			OBJ=$DPNI
			MAC_ADDR1=$MAC_ADDR2
		else
			TEMP=$(restool dprc connect dprc.1 --endpoint1=$DPNI --endpoint2=$OBJ)
			echo -e '\t'$OBJ" Linked with "$DPNI
			restool dprc sync
			TEMP=$(restool dprc assign dprc.1 --object=$DPNI --child=$DPRC --plugged=1)
			echo -e '\t'$DPNI "assigned to " $DPRC
			restool dprc sync
			TEMP=$(restool dprc assign dprc.1 --object=$OBJ --child=$DPRC --plugged=1)
			echo -e '\t'$OBJ "assigned to " $DPRC
		fi
		echo
		if [[ $MAC_ADDR1 ]]
		then
			echo -e $GREEN $OBJ "("$MAC_ADDR1") <--------connected------>" $DPNI "("$MAC_ADDR2")"$NC
		elif [[ $OBJ ]]
		then
			echo -e $GREEN $OBJ" <--------connected------>" $DPNI "("$MAC_ADDR2")"$NC
		else
			echo -e $GREEN $DPNI "("$MAC_ADDR2") UNCONNECTED" $NC
		fi
		echo
		OBJ=
		num=`expr $num + 1`
		if [[ ${!num} == "-b" ]]
		then
			num=`expr $num + 2`
			continue;
		fi
	done
	echo
	echo "******* End of parsing ARGS *******"
	echo

	DPMCP=$(restool dpmcp create | head -1 | cut -f1 -d ' ')
	echo $DPMCP "Created"
	#/* DPBP objects creation*/
	DPBP=$(restool dpbp create | head -1 | cut -f1 -d ' ')
	echo $DPBP "Created"
	DPBP1=$(restool dpbp create | head -1 | cut -f1 -d ' ')
	echo $DPBP1 "Created"
	DPBP2=$(restool dpbp create | head -1 | cut -f1 -d ' ')
	echo $DPBP2 "Created"
	DPBP3=$(restool dpbp create | head -1 | cut -f1 -d ' ')
	echo $DPBP3 "Created"
	#/* DPCON objects creation*/
	DPCON=$(restool dpcon create --num-priorities=$DPCON_PRIORITIES | head -1 | cut -f1 -d ' ')
	echo $DPCON "Created"
	DPCON1=$(restool dpcon create --num-priorities=$DPCON_PRIORITIES | head -1 | cut -f1 -d ' ')
	echo $DPCON1 "Created"
	DPCON2=$(restool dpcon create --num-priorities=$DPCON_PRIORITIES | head -1 | cut -f1 -d ' ')
	echo $DPCON2 "Created"
	DPCON3=$(restool dpcon create --num-priorities=$DPCON_PRIORITIES | head -1 | cut -f1 -d ' ')
	echo $DPCON3 "Created"
	DPCON4=$(restool dpcon create --num-priorities=$DPCON_PRIORITIES | head -1 | cut -f1 -d ' ')
	echo $DPCON4 "Created"
	#/* DPSECI objects creation*/
	DPSEC=$(restool dpseci create --num-queues=$DPSECI_QUEUES --priorities=$DPSECI_PRIORITIES | head -1 | cut -f1 -d ' ')
	echo $DPSEC "Created"
	#/* DPIO objects creation*/
	DPIO=$(restool dpio create --channel-mode=DPIO_LOCAL_CHANNEL --num-priorities=$DPIO_PRIORITIES | head -1 | cut -f1 -d ' ')
	echo $DPIO "Created"
	DPIO1=$(restool dpio create --channel-mode=DPIO_LOCAL_CHANNEL --num-priorities=$DPIO_PRIORITIES | head -1 | cut -f1 -d ' ')
	echo $DPIO1 "Created"
	DPIO2=$(restool dpio create --channel-mode=DPIO_LOCAL_CHANNEL --num-priorities=$DPIO_PRIORITIES | head -1 | cut -f1 -d ' ')
	echo $DPIO2 "Created"
	DPIO3=$(restool dpio create --channel-mode=DPIO_LOCAL_CHANNEL --num-priorities=$DPIO_PRIORITIES | head -1 | cut -f1 -d ' ')
	echo $DPIO3 "Created"
	DPIO4=$(restool dpio create --channel-mode=DPIO_LOCAL_CHANNEL --num-priorities=$DPIO_PRIORITIES | head -1 | cut -f1 -d ' ')
	echo $DPIO4 "Created"
	DPIO5=$(restool dpio create --channel-mode=DPIO_LOCAL_CHANNEL --num-priorities=$DPIO_PRIORITIES | head -1 | cut -f1 -d ' ')
	echo $DPIO5 "Created"
	DPIO6=$(restool dpio create --channel-mode=DPIO_LOCAL_CHANNEL --num-priorities=$DPIO_PRIORITIES | head -1 | cut -f1 -d ' ')
	echo $DPIO6 "Created"
	DPIO7=$(restool dpio create --channel-mode=DPIO_LOCAL_CHANNEL --num-priorities=$DPIO_PRIORITIES | head -1 | cut -f1 -d ' ')
	echo $DPIO7 "Created"
	DPIO8=$(restool dpio create --channel-mode=DPIO_LOCAL_CHANNEL --num-priorities=$DPIO_PRIORITIES | head -1 | cut -f1 -d ' ')
	echo $DPIO8 "Created"
	DPIO9=$(restool dpio create --channel-mode=DPIO_LOCAL_CHANNEL --num-priorities=$DPIO_PRIORITIES | head -1 | cut -f1 -d ' ')
	echo $DPIO9 "Created"

	# Create DPCI's for software queues
	DPCI=$(restool dpci create | head -1 | cut -f1 -d ' ')
	echo $DPCI "Created"
	DPCI1=$(restool dpci create | head -1 | cut -f1 -d ' ')
	echo $DPCI1 "Created"
	DPCI2=$(restool dpci create | head -1 | cut -f1 -d ' ')
	echo $DPCI2 "Created"
	DPCI3=$(restool dpci create | head -1 | cut -f1 -d ' ')
	echo $DPCI3 "Created"
	DPCI4=$(restool dpci create | head -1 | cut -f1 -d ' ')
	echo $DPCI4 "Created"
	DPCI5=$(restool dpci create | head -1 | cut -f1 -d ' ')
	echo $DPCI5 "Created"
	DPCI6=$(restool dpci create | head -1 | cut -f1 -d ' ')
	echo $DPCI6 "Created"
	DPCI7=$(restool dpci create | head -1 | cut -f1 -d ' ')
	echo $DPCI7 "Created"
	DPCI8=$(restool dpci create | head -1 | cut -f1 -d ' ')
	echo $DPCI8 "Created"
	DPCI9=$(restool dpci create | head -1 | cut -f1 -d ' ')
	echo $DPCI9 "Created"

	restool dprc sync
	TEMP=$(restool dprc connect dprc.1 --endpoint1=$DPCI --endpoint2=$DPCI1)
	echo  $DPCI" Linked with "$DPCI1
	TEMP=$(restool dprc connect dprc.1 --endpoint1=$DPCI2 --endpoint2=$DPCI3)
	echo  $DPCI2" Linked with "$DPCI3
	TEMP=$(restool dprc connect dprc.1 --endpoint1=$DPCI4 --endpoint2=$DPCI5)
	echo  $DPCI4" Linked with "$DPCI5
	TEMP=$(restool dprc connect dprc.1 --endpoint1=$DPCI6 --endpoint2=$DPCI7)
	echo  $DPCI6" Linked with "$DPCI7
	TEMP=$(restool dprc connect dprc.1 --endpoint1=$DPCI8 --endpoint2=$DPCI9)
	echo  $DPCI8" Linked with "$DPCI9
	restool dprc sync

	#/* Assigning the resources to newly created DPRC*/

	restool dprc sync
	TEMP=$(restool dprc assign dprc.1 --object=$DPBP --child=$DPRC --plugged=1)
	echo $DPBP "assigned to " $DPRC
	restool dprc sync
	TEMP=$(restool dprc assign dprc.1 --object=$DPBP1 --child=$DPRC --plugged=1)
	echo $DPBP1 "assigned to " $DPRC
	restool dprc sync
	TEMP=$(restool dprc assign dprc.1 --object=$DPBP2 --child=$DPRC --plugged=1)
	echo $DPBP2 "assigned to " $DPRC
	restool dprc sync
	TEMP=$(restool dprc assign dprc.1 --object=$DPBP3 --child=$DPRC --plugged=1)
	echo $DPBP3 "assigned to " $DPRC
	restool dprc sync
	TEMP=$(restool dprc assign dprc.1 --object=$DPCON --child=$DPRC --plugged=1)
	echo $DPCON "assigned to " $DPRC
	restool dprc sync
	TEMP=$(restool dprc assign dprc.1 --object=$DPCON1 --child=$DPRC --plugged=1)
	echo $DPCON1 "assigned to " $DPRC
	restool dprc sync
	TEMP=$(restool dprc assign dprc.1 --object=$DPCON2 --child=$DPRC --plugged=1)
	echo $DPCON2 "assigned to " $DPRC
	restool dprc sync
	TEMP=$(restool dprc assign dprc.1 --object=$DPCON3 --child=$DPRC --plugged=1)
	echo $DPCON3 "assigned to " $DPRC
	restool dprc sync
	TEMP=$(restool dprc assign dprc.1 --object=$DPCON4 --child=$DPRC --plugged=1)
	echo $DPCON4 "assigned to " $DPRC
	restool dprc sync
	TEMP=$(restool dprc assign dprc.1 --object=$DPSEC --child=$DPRC --plugged=1)
	echo $DPSEC "assigned to " $DPRC
	restool dprc sync
	TEMP=$(restool dprc assign dprc.1 --object=$DPIO --child=$DPRC --plugged=1)
	echo $DPIO "assigned to "$DPRC
	restool dprc sync
	TEMP=$(restool dprc assign dprc.1 --object=$DPIO1 --child=$DPRC --plugged=1)
	echo $DPIO1 "assigned to "$DPRC
	restool dprc sync
	TEMP=$(restool dprc assign dprc.1 --object=$DPIO2 --child=$DPRC --plugged=1)
	echo $DPIO2 "assigned to "$DPRC
	restool dprc sync
	TEMP=$(restool dprc assign dprc.1 --object=$DPIO3 --child=$DPRC --plugged=1)
	echo $DPIO3 "assigned to "$DPRC
	restool dprc sync
	TEMP=$(restool dprc assign dprc.1 --object=$DPIO4 --child=$DPRC --plugged=1)
	echo $DPIO4 "assigned to "$DPRC
	restool dprc sync
	TEMP=$(restool dprc assign dprc.1 --object=$DPIO5 --child=$DPRC --plugged=1)
	echo $DPIO5 "assigned to "$DPRC
	restool dprc sync
	TEMP=$(restool dprc assign dprc.1 --object=$DPIO6 --child=$DPRC --plugged=1)
	echo $DPIO6 "assigned to "$DPRC
	restool dprc sync
	TEMP=$(restool dprc assign dprc.1 --object=$DPIO7 --child=$DPRC --plugged=1)
	echo $DPIO7 "assigned to "$DPRC
	restool dprc sync
	TEMP=$(restool dprc assign dprc.1 --object=$DPIO8 --child=$DPRC --plugged=1)
	echo $DPIO8 "assigned to "$DPRC
	restool dprc sync
	TEMP=$(restool dprc assign dprc.1 --object=$DPIO9 --child=$DPRC --plugged=1)
	echo $DPIO9 "assigned to "$DPRC
	restool dprc sync
	TEMP=$(restool dprc assign dprc.1 --object=$DPMCP --child=$DPRC --plugged=1)
	echo $DPMCP "assigned to "$DPRC
	restool dprc sync
	TEMP=$(restool dprc assign dprc.1 --object=$DPCI --child=$DPRC --plugged=1)
	echo $DPCI "assigned to "$DPRC
	restool dprc sync
	TEMP=$(restool dprc assign dprc.1 --object=$DPCI1 --child=$DPRC --plugged=1)
	echo $DPCI1 "assigned to "$DPRC
	restool dprc sync
	TEMP=$(restool dprc assign dprc.1 --object=$DPCI2 --child=$DPRC --plugged=1)
	echo $DPCI2 "assigned to "$DPRC
	restool dprc sync
	TEMP=$(restool dprc assign dprc.1 --object=$DPCI3 --child=$DPRC --plugged=1)
	echo $DPCI3 "assigned to "$DPRC
	restool dprc sync
	TEMP=$(restool dprc assign dprc.1 --object=$DPCI4 --child=$DPRC --plugged=1)
	echo $DPCI4 "assigned to "$DPRC
	restool dprc sync
	TEMP=$(restool dprc assign dprc.1 --object=$DPCI5 --child=$DPRC --plugged=1)
	echo $DPCI5 "assigned to "$DPRC
	restool dprc sync
	TEMP=$(restool dprc assign dprc.1 --object=$DPCI6 --child=$DPRC --plugged=1)
	echo $DPCI6 "assigned to "$DPRC
	restool dprc sync
	TEMP=$(restool dprc assign dprc.1 --object=$DPCI7 --child=$DPRC --plugged=1)
	echo $DPCI7 "assigned to "$DPRC
	restool dprc sync
	TEMP=$(restool dprc assign dprc.1 --object=$DPCI8 --child=$DPRC --plugged=1)
	echo $DPCI8 "assigned to "$DPRC
	restool dprc sync
	TEMP=$(restool dprc assign dprc.1 --object=$DPCI9 --child=$DPRC --plugged=1)
	echo $DPCI9 "assigned to "$DPRC
	restool dprc sync

	# Mount HUGETLB Pages first
	HUGE=$(grep -E '/mnt/\<hugepages\>.*hugetlbfs' /proc/mounts)
	if [[ -z $HUGE ]]
	then
		mkdir /mnt/hugepages
		mount -t hugetlbfs none /mnt/hugepages
	else
		echo
		echo
		echo "Already mounted :  " $HUGE
		echo
	fi
	echo
	if [ -e /sys/module/vfio_iommu_type1 ];
	then
	        echo "#1)    Allow unsafe interrupts"
	        echo 1 > /sys/module/vfio_iommu_type1/parameters/allow_unsafe_interrupts
	else
	        echo -e $RED" Can't Run NADK without VFIO support"$NC
		[[ "${BASH_SOURCE[0]}" != $0 ]] && return || exit
	fi
	if [ -e $DPRC_LOC ];
	then
		echo vfio-fsl-mc > /sys/bus/fsl-mc/devices/$DPRC/driver_override
		echo "#1.2)    Bind "$DPRC" to VFIO driver"
		echo $DPRC > /sys/bus/fsl-mc/drivers/vfio-fsl-mc/bind
	fi

	ls /dev/vfio/
	echo
	echo -e "USE "$GREEN $DPRC $NC" FOR YOUR APPLICATIONS"
	rm script_help
	echo

else
	echo
	echo -e '\t'$RED"Arguments missing"$NC
	cat script_help
	rm script_help
fi
