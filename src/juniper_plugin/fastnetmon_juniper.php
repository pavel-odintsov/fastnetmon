#!/usr/bin/php
<?php
/*****************************
 *
 * Juniper PHP Integration for Fastnetmon
 *
 * This script connect to Juniper Router and add or remove a blackhole's rule for the IP attack
 * 
 * Author: Christian David <davidchristia@gmail.com>
 *
 * Credits for the Netconf API By Juniper/netconf-php <https://github.com/Juniper/netconf-php>
 * Script based on Mikrotik Plugin by Maximiliano Dobladez <info@mkesolutions.net>
 *
 * Made based on a MX5 CLI and not tested yet, please feedback-us in Issues on github
 * 
 * LICENSE: GPLv2 GNU GENERAL PUBLIC LICENSE
 *
 *
 * v1.0 - 5 Dec 18 - initial version
 ******************************/

define( "_VER", '1.0' );

$date = date("Y-m-d H:i:s", time());

// You need to enable NETCONF on your juniper
// https://www.juniper.net/documentation/en_US/junos/topics/task/configuration/netconf-ssh-connection-establishing.html#task-netconf-service-over-ssh-enabling
$cfg['hostname'] = "10.0.0.1"; // Juniper IP
$cfg['port'] = 880; //NETCONF Port 
$cfg['username'] = "user"; //user
$cfg['password'] = "password"; //pass

/*
PARAMS(
    $argv[1] = STRING (IP)
    $argv[2] = STRING (ATTACK DIRECTION)
    $argv[3] = STRING (PPS)
    $argv[4] = STRING (ACTION = BAN OR UNBAN)
)
*/
$IP_ATTACK          = $argv[ 1 ];
$DIRECTION_ATTACK   = $argv[ 2 ];
$POWER_ATTACK       = $argv[ 3 ];
$ACTION_ATTACK      = $argv[ 4 ];
if ( $argc <= 4 ) {
    $msg .= "Juniper API Integration for FastNetMon  - Ver: " . _VER . "\n";
    $msg .= "missing arguments";
    $msg .= "php fastnetmon_juniper.php [IP] [data_direction] [pps_as_string] [action]  \n";
    echo $msg;
    exit( 1 );
}
//NOTE  help
if ( $argv[ 1 ] == "help" ) {
    $msg = "Juniper API Integration for FastNetMon  - Ver: " . _VER;
    echo $msg;    
    exit( 1 );
}

require_once "netconf/netconf/Device.php";
$conn = new Device($cfg);
switch($ACTION_ATTACK){
    case 'ban':
        try{
            $desc = 'FastNetMon Community: IP '. $IP_ATTACK .' unblocked because '. $DIRECTION_ATTACK .' attack with power '. $POWER_ATTACK .' pps | at '.$fecha_now;
            $conn->connect(); //Try conect or catch NetconfException (Wrong username, Timeout, Device not found, etc)
            $locked = $conn->lock_config(); //Equivalent of "configure exclusive" on Juniper CLI
            if($locked){
                //Community 65535:666 = BLACKHOLE
                $conn->load_set_configuration("set routing-options static route {$IP_ATTACK} community 65535:666 discard");
                $conn->commit();
            }
            $conn->unlock(); //Unlock the CLI
            $conn->close(); //Close the connection
            _log($desc);

        }
        catch(NetconfException $e){
            $msg = "Couldn't connect to " . $cfg['hostname'] . '\nLOG: '.$e;
            _log( $msg );
            echo $msg;
            exit( 1 );
        }
        break;
    case 'unban':
        try{
            $desc = 'FastNetMon Community: IP '. $IP_ATTACK .' remove from blacklist.';
            $conn->connect(); //Try conect or catch NetconfException (Wrong username, Timeout, Device not found, etc)
            $locked = $conn->lock_config(); //Equivalent of "configure exclusive" on Juniper CLI
            if($locked){
                $conn->load_set_configuration("delete routing-options static route {$IP_ATTACK}/32");
                $conn->commit();
            }
            $conn->unlock(); //Unlock the CLI
            $conn->close(); //Close the connection
            _log($desc);            
        }
        catch(NetconfException $e){
            $msg = "Couldn't connect to " . $cfg['hostname'] . '\nLOG: '.$e;
            _log( $msg );
            echo $msg;
            exit( 1 );
        }
        break;
    default:
        $msg = "Juniper API Integration for FastNetMon  - Ver: " . _VER;
        echo $msg;    
        exit( 1 );
        break;
}
/**
 * [_log Write a log file]
 * @param  [type] $msg [text to log]
 * @return [type]      
 */
function _log( $msg ) {
    $FILE_LOG_TMP = "/tmp/fastnetmon_api_juniper.log";
    if ( !file_exists( $FILE_LOG_TMP ) )    exec( "echo `date` \"- [FASTNETMON] - " . $msg . " \" > " . $FILE_LOG_TMP );
    else exec( "echo `date` \"- [FASTNETMON] - " . $msg . " \" >> " . $FILE_LOG_TMP );
     
}
?>
