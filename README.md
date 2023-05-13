Minetools (WIP)
==================
Simple Rcon class for php, for now, in the future will work with query and ping.

## Example
For this script to work, rcon must be enabled on the server, by setting `enable-rcon=true` in the server's `server.properties` file. A password must also be set, and provided in the script.

```php
$host = 'some.minecraftserver.com'; // Server host name or IP
$port = 25575;                      // Port rcon is listening on
$password = 'server-rcon-password'; // rcon.password setting set in server.properties
$timeout = 3;                       // How long to timeout.

use Minetools\Protocols\Rcon;

$rcon = new Rcon($host, $port, $password, $timeout);

if ($rcon)
{
  $rcon->sendCommand("say Hello World!");
}
```
