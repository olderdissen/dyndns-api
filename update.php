<?
chdir(__DIR__);

$config = array
	(
	"username" => "",
	"password" => "",
	"hostname" => "localhost",
	"myip" => = "0.0.0.0",
	"wildcard" => "OFF",
	"mx" => "",
	"backmx" => "NO",
	"offline" => "",
	"status" => "",
	"system" => "dyndns",
	"url" => ""
	);

################################################################################
# get myip by connection
################################################################################

foreach(array("myip" => "REMOTE_ADDR") as $key => $value)
	$config[$key] = (isset($_SERVER[$value]) === false ? $config[$key] : $_SERVER[$value]);

################################################################################
# get myip by users query
################################################################################

foreach($config as $key => $value)
	$config[$key] = (isset($_GET[$key]) === false ? $config[$key] : $_GET[$key]);

################################################################################
# get username and password by header
################################################################################

foreach(array("username" => "PHP_AUTH_USER", "password" => "PHP_AUTH_PW") as $key => $value)
	$config[$key] = (isset($_SERVER[$value]) === false ? "" : $_SERVER[$value]);

################################################################################
# create status from users input
################################################################################

if(isset($config["username"]) === false)
	$config["status"] = "badauth";
elseif(strlen($config["username"]) == 0)
	$config["status"] = "badauth";
elseif(isset($config["password"]) === false)
	$config["status"] = "badauth";
elseif(strlen($config["password"]) == 0)
	$config["status"] = "badauth";
elseif(file_exists("data/" . $config["username"] . ".pass") === false)
	$config["status"] = "badauth";
elseif($config["password"] != file_get_contents("data/" . $config["username"] . ".pass"))
	$config["status"] = "badauth";
elseif(file_exists("data/" . $config["username"] . ".ip") === false)
	$config["status"] = "good";
#elseif((filemtime("data/" . $config["username"] . ".ip") + 30) > time()) # 30 seconds
#	$config["status"] = "abuse";
elseif(isset($config["myip"]) === false)
	$config["status"] = "abuse";
elseif(strlen($config["myip"]) == 0)
	$config["status"] = "abuse";
elseif(strpos($config["myip"], ".") === false)
	$config["status"] = "abuse";
elseif(count(explode(".", $config["myip"])) != 4)
	$config["status"] = "abuse";
elseif(ip2long($config["myip"]) === false)
	$config["status"] = "abuse";
#elseif(filter_var($config["myip"], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) == "")
#	$config["status"] = "abuse";
elseif(is_private_ip($config["myip"]) == 1)
	$config["status"] = "abuse";
elseif($config["myip"] == file_get_contents("data/" . $config["username"] . ".ip"))
	$config["status"] = "nochg";
else
	$config["status"] = "good";

header("Content-Type: text/plain");

if($config["status"] == "badauth")
	header("WWW-Authenticate: basic realm=\"dyndns\"");

if($config["status"] == "abuse")
	die("...");

if($config["status"] == "nochg")
	touch("data/" . $config["username"] . ".ip");

if($config["status"] == "good")
	file_put_contents("data/" . $config["username"] . ".ip", $config["myip"]);

if($config["status"] == "good")
	exec("sudo php named-update-zonefiles.php");

print($config["status"]);

################################################################################
# http://www.iana.org/assignments/ipv4-address-space/ipv4-address-space.txt
################################################################################

function is_private_ip($ip)
	{
	$ranges = array
		(
		array("0.0.0.0", "0.255.255.255"),
		array("10.0.0.0", "10.255.255.255"), # CLASS A
		array("100.64.0.0", "100.127.255.255"),
		array("127.0.0.0", "127.255.255.255"),
		array("169.254.0.0", "169.254.255.255"),
		array("172.16.0.0", "172.31.255.255"), # CLASS B
		array("192.0.0.0", "192.0.0.255"),
		array("192.0.2.0", "192.0.2.255"),
		array("192.18.0.0", "192.19.255.255"),
		array("192.88.99.0", "192.88.99.255"),
		array("192.88.99.1", "192.88.99.1"),
		array("192.88.99.2", "192.88.99.2"),
		array("192.168.0.0", "192.168.255.255"), # CLASS C
		array("198.51.100.0", "192.51.100.255"),
		array("203.0.113.0", "203.0.113.255"),
		array("255.255.255.255", "255.255.255.255"),
		array("224.0.0.0", "239.255.255.255"), # CLASS D
		array("240.0.0.0", "255.255.255.255") # CLASS E
		);

	foreach($ranges as $id => $range)
		{
		list($first, $last) = $range;

		if(ip2long($ip) < ip2long($first))
			continue;

		if(ip2long($ip) > ip2long($last))
			continue;

		return(1);
		}

	return(0);
	}
?>
