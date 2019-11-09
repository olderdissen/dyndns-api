<?
chdir(__DIR__);

# RESOURCES:
# https://help.dyn.com/remote-access-api/

define("DYNDNS_AUTH", false);
define("DYNDNS_SYNC", false);
define("DYNDNS_ZONE", "example.com");
define("DYNDNS_HOST", "127.0.0.1");
define("DYNDNS_PASS", "rndc-key 000000000000000000000000");

$handle = [];

$users = [
	"user" => "pass",
	"test" => "test"
	];

################################################################################

if(isset($_SERVER["PHP_AUTH_USER"]) && strlen($_SERVER["PHP_AUTH_USER"]))
	$handle["username"] = $_SERVER["PHP_AUTH_USER"];

if(isset($_GET["username"]) && strlen($_GET["username"]))
	$handle["username"] = $_GET["username"];

if(isset($_SERVER["PHP_AUTH_PW"]) && strlen($_SERVER["PHP_AUTH_PW"]))
	$handle["password"] = $_SERVER["PHP_AUTH_PW"];

if(isset($_GET["password"]) && strlen($_GET["password"]))
	$handle["password"] = $_GET["password"];

if(isset($_SERVER["PHP_AUTH_USER"]) && strlen($_SERVER["PHP_AUTH_USER"]))
	$handle["hostname"] = $_SERVER["PHP_AUTH_USER"] . ".dyn." . DYNDNS_ZONE;

if(isset($_GET["username"]) && strlen($_GET["username"]))
	$handle["hostname"] = $_GET["username"] . ".dyn." . DYNDNS_ZONE;

if(isset($_GET["hostname"]) && strlen($_GET["hostname"]))
	$handle["hostname"] = $_GET["hostname"]; # trust in user

if(isset($_SERVER["REMOTE_ADDR"]) && strlen($_SERVER["REMOTE_ADDR"]))
	$handle["myip"] = $_SERVER["REMOTE_ADDR"];

if(isset($_GET["myip"]) && strlen($_GET["myip"]))
	$handle["myip"] = $_GET["myip"];
		
################################################################################

if(! defined("DYNDNS_HOST"))
	$handle["status"] = "DYNDNS_HOST not found";
elseif(! defined("DYNDNS_PASS"))
	$handle["status"] = "DYNDNS_PASS not found";
elseif(! defined("DYNDNS_ZONE"))
	$handle["status"] = "DYNDNS_ZONE not found";
elseif(! isset($handle["username"]))
	$handle["status"] = "badauth";
elseif(! strlen($handle["username"]))
	$handle["status"] = "badauth";
elseif(! isset($handle["password"]))
	$handle["status"] = "badauth";
elseif(! strlen($handle["password"]))
	$handle["status"] = "badauth";
elseif($handle["password"] != $users[$handle["username"]])
	$handle["status"] = "badauth";
elseif(! isset($handle["hostname"]))
	$handle["status"] = "notfqdn";
elseif(! strlen($handle["hostname"]))
	$handle["status"] = "notfqdn";
elseif(! isset($handle["myip"]))
	$handle["status"] = "abuse";
elseif(! strlen($handle["myip"]))
	$handle["status"] = "abuse";
elseif($handle["myip"] == "0.0.0.0")
	$handle["status"] = "good";
elseif(! ip2long($handle["myip"]))
	$handle["status"] = "abuse";
else
	$handle["status"] = "good";

################################################################################

if($handle["status"] == "badauth")
	if(defined("DYNDNS_AUTH") && DYNDNS_AUTH)
		header("WWW-Authenticate: basic realm=\"dyndns\"");

if($handle["status"] == "good")
	$handle["status"] = nsupdate($handle);

header("Content-Type: text/plain");

die($handle["status"]);

################################################################################

function nsupdate($handle)
	{
	$status = [];

	openlog("ddns", LOG_PID | LOG_PERROR, LOG_USER);

	foreach(explode(",", $handle["hostname"]) as $hostname)
		{
		$data = dns_get_record($hostname, DNS_A);

		if($data[0]["ip"] == $handle["myip"])
			$status[$hostname] = "nochg";
		else
			{
			$data = [
				"server " . DYNDNS_HOST,
				"key " . DYNDNS_PASS,
				"zone " . DYNDNS_ZONE . ".",
				"del " . $hostname . ". A",
				"add " . $hostname . ". 60 A " . $handle["myip"],
				"send",
				"quit"
				];

			$filename = tempnam(__DIR__, "nsupdate");

			if(! $filename)
				return("911");

			file_put_contents($filename, implode("\n", $data));

			$return_var = 0;

			system("nsupdate " . $filename, $return_var);

			if(! unlink($filename))
				return("911");

			$status[$hostname] = ($return_var ? "nochg" : "good");
			}

		syslog(LOG_INFO, sprintf("%s %s", $hostname, $status[$hostname]));
		}

	closelog();

	if(defined("DYNDNS_SYNC") && DYNDNS_SYNC && in_array("good", $status))
		system("sudo rndc sync " . DYNDNS_ZONE . ".");

	return(implode("\n", $status));
	}
?>
