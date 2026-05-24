#!/usr/bin/php
<?php

/*****************************
 *
 * MikroTik RouterOS PHP API integration for FastNetMon  
 *
 * This script connect to router MikroTik and add or remove a blackhole's rule for the IP attack
 * 
 * Author: Maximiliano Dobladez info@mkesolutions.net
 *
 * http://maxid.com.ar | http://www.mkesolutions.net  
 *
 * for API MIKROTIK:
 * http://www.mikrotik.com
 * http://wiki.mikrotik.com/wiki/API_PHP_class
 *
 * LICENSE: GPLv2 GNU GENERAL PUBLIC LICENSE
 *
 *
 ******************************/

// Strict type checking
declare(strict_types=1);

error_reporting( E_ALL );
ini_set( 'display_errors', 'On' );

define( "_VER", '1.0' );

/* NOTE: YOU NEED TO ENABLE THE API ACCESS ON MIKROTIK */

/*

Example configuration file /etc/mikrotik_integration.json:

{
    "ip_mikrotik": "192.168.10.1",
    "api_user": "api",
    "api_pass": "api123"
}

*/

$config_path = "/etc/mikrotik_integration.json";

if ( !file_exists( $config_path ) ) {
    $msg = "Configuration file not found: " . $config_path;
    _log( $msg );
    echo $msg . "\n";
    exit( 1 );
}

$cfg = json_decode( file_get_contents( $config_path ), true );

if ( !is_array( $cfg ) ) {
    $msg = "Failed to parse configuration file: " . $config_path;
    _log( $msg );
    echo $msg . "\n";
    exit( 1 );
}

foreach ( [ 'ip_mikrotik', 'api_user', 'api_pass' ] as $key ) {
    if ( empty( $cfg[ $key ] ) ) {
        $msg = "Missing required config key: " . $key;
        _log( $msg );
        echo $msg . "\n";
        exit( 1 );
    }
}

//  help
if ( $argc > 1 && $argv[ 1 ] == "help" ) {
    $msg = "MikroTik's API Integration for FastNetMon - Ver: " . _VER;
    echo $msg;    
    exit(1);
}

/*

This script will get following params from FastNetMon:
    $1 client_ip_as_string
    $2 data_direction
    $3 pps_as_string
    $4 action (ban or unban)
*/

// Ensure that we got all required arguments
if ( $argc <= 4 ) {
    $msg = "MikroTik's API Integration for FastNetMon  - Ver: " . _VER . "\n";
    $msg .= "missing arguments";
    $msg .= "php fastnetmon_mikrotik.php [IP] [data_direction] [pps_as_string] [action]  \n";
    
    _log( $msg );
    echo $msg;
    exit( 1 );
}


// IPv4 or IPv6 address of attack
$IP_ATTACK = $argv[ 1 ];
if ( filter_var( $IP_ATTACK, FILTER_VALIDATE_IP ) === false ) {
    $msg = "Invalid IP address: " . $IP_ATTACK;
    _log( $msg );
    echo $msg . "\n";
    exit( 1 );
}

// incoming, outgoing or unknown
$DIRECTION_ATTACK = $argv[ 2 ];
if ( !in_array( $DIRECTION_ATTACK, [ 'incoming', 'outgoing', 'unknown' ], true ) ) {
    $msg = "Invalid direction: " . $DIRECTION_ATTACK . ". Must be incoming, outgoing, or unknown.";
    _log( $msg );
    echo $msg . "\n";
    exit( 1 );
}

// Power of attack in packets per second
$POWER_ATTACK = $argv[ 3 ];
if ( !ctype_digit( $POWER_ATTACK ) ) {
    $msg = "Invalid pps value: " . $POWER_ATTACK . ". Must be a positive integer.";
    _log( $msg );
    echo $msg . "\n";
    exit( 1 );
}

// Action: ban or unban
$ACTION_ATTACK = $argv[ 4 ];
if ( !in_array( $ACTION_ATTACK, [ 'ban', 'unban' ], true ) ) {
    $msg = "Invalid action: " . $ACTION_ATTACK . ". Must be ban or unban.";
    _log( $msg );
    echo $msg . "\n";
    exit( 1 );
}

require_once "routeros_api.php";
$API = new RouterosAPI();

// $API->debug = true;
if (! $API->connect( $cfg[ 'ip_mikrotik' ], $cfg[ 'api_user' ], $cfg[ 'api_pass' ] ) ) {
    // can't connect
    $msg = "Couldn't connect to " . $cfg[ 'ip_mikrotik' ];
    _log( $msg );
    echo $msg;
    exit( 1 );
} 

$time_now = date("Y-m-d H:i:s", time());

//add Blocking by route blackhole
if ( $ACTION_ATTACK == "ban" ) {
    $comment_rule = 'FastNetMon Community: IP ' . $IP_ATTACK . ' blocked because ' . $DIRECTION_ATTACK . ' attack with power ' . $POWER_ATTACK . ' pps | at '.$time_now;
    
    $API->write( '/ip/route/add', false );
    $API->write( '=dst-address=' . $IP_ATTACK, false );
    $API->write( '=type=blackhole', false );
    $API->write( '=bgp-communities=65535:666', false );
    $API->write( '=comment=' . $comment_rule );
    
    // Log to router syslog. Useful for alerting and Graylog reporting
    $API->write( '/log/info', false );
    $API->write( '=message=' . $comment_rule );
    $ret = $API->read();

    if ($ret) _log( $comment_rule );
} elseif ($ACTION_ATTACK == "unban" ) {
    // remove the blackhole rule 
    $comment_rule = 'FastNetMon Community: IP ' . $IP_ATTACK . ' remove from blacklist ';
    $API->write( '/ip/route/print', false );
    $API->write( '?dst-address=' . $IP_ATTACK . "/32" );
    
    $ID_ARRAY = $API->read();
    $API->write( '/ip/route/remove', false );
    $API->write( '=.id=' . $ID_ARRAY[ 0 ][ '.id' ] );
    
    // Log to router syslog. Useful for alerting and Graylog reporting
    $API->write( '/log/info', false );
    $API->write( '=message=' . $comment_rule );
    $ret = $API->read();

    if ($ret) _log( $comment_rule );
} else {
    $msg = "Unknown action: " . $ACTION_ATTACK;
    
    _log( $msg );
    echo $msg;
    exit( 1 );
}
/**
 * [_log Write a log file]
 * @param  [type] $msg [text to log]
 * @return [type]      
 */
function _log( $msg ) {
    $FILE_LOG_TMP = "/tmp/fastnetmon_api_mikrotik.log";
    $line = date("D M j H:i:s T Y") . " - [FASTNETMON] - " . $msg . "\n";
    file_put_contents( $FILE_LOG_TMP, $line, FILE_APPEND );
}

?>
