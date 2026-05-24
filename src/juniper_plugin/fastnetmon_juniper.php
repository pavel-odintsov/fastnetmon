#!/usr/bin/php
<?php
declare(strict_types=1);

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

error_reporting(E_ALL);
ini_set('display_errors', 'On');

define("_VER", '1.0');

/* NOTE: YOU NEED TO ENABLE NETCONF ON YOUR JUNIPER */
/* https://www.juniper.net/documentation/en_US/junos/topics/task/configuration/netconf-ssh-connection-establishing.html#task-netconf-service-over-ssh-enabling */

/*

Example configuration file /etc/juniper_integration.json:

{
    "hostname": "10.0.0.1",
    "port": 880,
    "username": "user",
    "password": "password"
}

*/

$config_path = "/etc/juniper_integration.json";

if (!file_exists($config_path)) {
    $msg = "Configuration file not found: " . $config_path;
    _log($msg);
    echo $msg . "\n";
    exit(1);
}

$cfg = json_decode(file_get_contents($config_path), true);

if (!is_array($cfg)) {
    $msg = "Failed to parse configuration file: " . $config_path;
    _log($msg);
    echo $msg . "\n";
    exit(1);
}

foreach (['hostname', 'port', 'username', 'password'] as $key) {
    if (empty($cfg[$key])) {
        $msg = "Missing required config key: " . $key;
        _log($msg);
        echo $msg . "\n";
        exit(1);
    }
}

// help
if ($argc > 1 && $argv[1] == "help") {
    $msg = "Juniper API Integration for FastNetMon - Ver: " . _VER;
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
if ($argc <= 4) {
    $msg = "Juniper API Integration for FastNetMon - Ver: " . _VER . "\n";
    $msg .= "missing arguments\n";
    $msg .= "php fastnetmon_juniper.php [IP] [data_direction] [pps_as_string] [action]\n";

    _log($msg);
    echo $msg;
    exit(1);
}

// IPv4 or IPv6 address of attack
$IP_ATTACK = $argv[1];
if (filter_var($IP_ATTACK, FILTER_VALIDATE_IP) === false) {
    $msg = "Invalid IP address: " . $IP_ATTACK;
    _log($msg);
    echo $msg . "\n";
    exit(1);
}

// incoming, outgoing or unknown
$DIRECTION_ATTACK = $argv[2];
if (!in_array($DIRECTION_ATTACK, ['incoming', 'outgoing', 'unknown'], true)) {
    $msg = "Invalid direction: " . $DIRECTION_ATTACK . ". Must be incoming, outgoing, or unknown.";
    _log($msg);
    echo $msg . "\n";
    exit(1);
}

// Power of attack in packets per second
$POWER_ATTACK = $argv[3];
if (!ctype_digit($POWER_ATTACK)) {
    $msg = "Invalid pps value: " . $POWER_ATTACK . ". Must be a positive integer.";
    _log($msg);
    echo $msg . "\n";
    exit(1);
}

// Action: ban or unban
$ACTION_ATTACK = $argv[4];
if (!in_array($ACTION_ATTACK, ['ban', 'unban'], true)) {
    $msg = "Invalid action: " . $ACTION_ATTACK . ". Must be ban or unban.";
    _log($msg);
    echo $msg . "\n";
    exit(1);
}

$netconf_path = __DIR__ . "/netconf/netconf/Device.php";
if (!file_exists($netconf_path)) {
    $msg = "Netconf library not found: " . $netconf_path;
    _log($msg);
    echo $msg . "\n";
    exit(1);
}

if (!function_exists('expect_popen')) {
    $msg = "PHP expect extension is required but not installed. Install it with PECL: pecl install expect";
    _log($msg);
    echo $msg . "\n";
    exit(1);
}

set_include_path(get_include_path() . PATH_SEPARATOR . dirname($netconf_path));
require_once $netconf_path;
$conn = new Device($cfg);

$time_now = date("Y-m-d H:i:s", time());

if ($ACTION_ATTACK == 'ban') {
    try {
        $desc = 'FastNetMon Community: IP ' . $IP_ATTACK . ' blocked because ' . $DIRECTION_ATTACK . ' attack with power ' . $POWER_ATTACK . ' pps | at ' . $time_now;
        $conn->connect();
        $locked = $conn->lock_config();

        if ($locked) {
            // Community 65535:666 = BLACKHOLE
            $conn->load_set_configuration("set routing-options static route {$IP_ATTACK} community 65535:666 discard");
            $conn->commit();
        }
        $conn->unlock();
        $conn->close();
        _log($desc);
        echo $desc . "\n";
    } catch (NetconfException $e) {
        $msg = "Couldn't connect to " . $cfg['hostname'] . " - " . $e->getMessage();
        _log($msg);
        echo $msg . "\n";
        exit(1);
    } catch (Exception $e) {
        $msg = "Ban failed for " . $IP_ATTACK . " - " . $e->getMessage();
        _log($msg);
        echo $msg . "\n";
        exit(1);
    }
} elseif ($ACTION_ATTACK == 'unban') {
    try {
        $desc = 'FastNetMon Community: IP ' . $IP_ATTACK . ' remove from blacklist.';
        $conn->connect();
        $locked = $conn->lock_config();
        if ($locked) {
            $conn->load_set_configuration("delete routing-options static route {$IP_ATTACK}/32");
            $conn->commit();
        }
        $conn->unlock();
        $conn->close();
        _log($desc);
        echo $desc . "\n";
    } catch (NetconfException $e) {
        $msg = "Couldn't connect to " . $cfg['hostname'] . " - " . $e->getMessage();
        _log($msg);
        echo $msg . "\n";
        exit(1);
    } catch (Exception $e) {
        $msg = "Unban failed for " . $IP_ATTACK . " - " . $e->getMessage();
        _log($msg);
        echo $msg . "\n";
        exit(1);
    }
} else {
    $msg = "Unknown action: " . $ACTION_ATTACK;
    _log($msg);
    echo $msg . "\n";
    exit(1);
}

/**
 * [_log Write a log file]
 * @param  string $msg text to log
 */
function _log(string $msg): void
{
    $FILE_LOG_TMP = "/tmp/fastnetmon_api_juniper.log";
    $line = date("D M j H:i:s T Y") . " - [FASTNETMON] - " . $msg . "\n";
    file_put_contents($FILE_LOG_TMP, $line, FILE_APPEND);
}

?>