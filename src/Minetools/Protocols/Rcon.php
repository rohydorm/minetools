<?php
/**
 * See https://developer.valvesoftware.com/wiki/Source_RCON_Protocol for
 * more information about Source RCON Packets
 *
 * PHP Version 8.2
 *
 * @copyright 2013-2017 Chris Churchwell
 * @author thedudeguy
 * @copyright 2023 
 * @author Rohydorm
 * @link https://github.com/rohydorm/PHP-Minecraft-Rcon
 */

namespace Minetools\Protocols;

class Rcon
{
    private $socket;

    private bool $authorized = false;
    private $lastResponse = '';

    final public const PACKET_AUTHORIZE = 5;
    final public const PACKET_COMMAND = 6;
    final public const PACKET_COMMAND_ENDING = 7;

    final public const SERVERDATA_AUTH = 3;
    final public const SERVERDATA_AUTH_RESPONSE = 2;
    final public const SERVERDATA_EXECCOMMAND = 2;
    final public const SERVERDATA_RESPONSE_VALUE = 0;

    /**
     * Create a new instance of the Rcon class.
     *
     * @param string $host
     * @param integer $port
     * @param string $password
     * @param integer $timeout
     */
    public function __construct(
        private string $host,
        private int $port,
        private string $password,
        private int $timeout)
    {
        $this->connect();
    }

    /**
     * Get the latest response from the server.
     *
     * @param bool $clearFormat
     * 
     * @return string
     */
    public function getResponse(bool $clearFormat) : string
    {
        return match($clearFormat) {
            true => self::cleanResponse($this->lastResponse),
            false => $this->lastResponse,
        };
    }

    /**
     * Connect to a server.
     *
     * @return boolean
     */
    private function connect() : bool
    {
        $this->socket = fsockopen($this->host, $this->port, $errno, $errstr, $this->timeout);

        if (!$this->socket) {
            $this->lastResponse = $errstr;
            return false;
        }

        //set timeout
        stream_set_timeout($this->socket, 3, 0);

        // check authorization
        return self::authorize();
    }

    /**
     * Disconnect from server.
     *
     * @return void
     */
    public function disconnect() : void
    {
        if ($this->socket) {
            fclose($this->socket);
        }
    }

    /**
     * True if socket is connected and authorized.
     *
     * @return boolean
     */
    public function isConnected() : bool
    {
        return $this->authorized;
    }

    /**
     * Send a command to the connected server.
     *
     * @param string $command
     *
     * @return boolean|mixed
     */
    public function sendCommand(string $command, bool $clearFormat = true) : mixed
    {
        if (!$this->isConnected()) {
            self::connect();
        }

        // send command packet
        self::writePacket(self::PACKET_COMMAND, self::SERVERDATA_EXECCOMMAND, $command);

        // send additional packet to determine last response packet later
        self::writePacket(self::PACKET_COMMAND_ENDING, self::SERVERDATA_EXECCOMMAND, 'ping');

        // get response
        $response = '';
        $response_packet = self::readPacket();
        while ($response_packet['id'] == self::PACKET_COMMAND && $response_packet['type'] == self::SERVERDATA_RESPONSE_VALUE) {
            $response .= $response_packet['body'];
            $response_packet = self::readPacket();
        }
        $response = substr($response, 0, -3);
        if ($response != '') {
            $this->lastResponse = match($clearFormat) {
                true => self::cleanResponse($response),
                false => $response,
            };
            return $response;
        }

        return false;
    }

    /**
     * Clear Minecraft format
     * 
     * @param string $response
     * 
     * @return string
     */
    private function cleanResponse(string $response) : string
    {
        return filter_var(preg_replace('/\xa7./','',$response), FILTER_SANITIZE_SPECIAL_CHARS, FILTER_FLAG_STRIP_LOW | FILTER_FLAG_STRIP_HIGH);
    }

    /**
     * Log into the server with the given credentials.
     *
     * @return boolean
     */
    private function authorize() : bool
    {
        self::writePacket(self::PACKET_AUTHORIZE, self::SERVERDATA_AUTH, $this->password);
        $response_packet = self::readPacket();

        if ($response_packet['type'] == self::SERVERDATA_AUTH_RESPONSE && $response_packet['id'] == self::PACKET_AUTHORIZE) {
            $this->authorized = true;
            return true;
        }

        $this->disconnect();
        return false;
    }

    /**
     * Writes a packet to the socket stream.
     *
     * @param $packetId
     * @param $packetType
     * @param string $packetBody
     *
     * @return void
     */
    private function writePacket($packetId, $packetType, $packetBody) : void
    {
        /*
		Size			32-bit little-endian Signed Integer	 	Varies, see below.
		ID				32-bit little-endian Signed Integer		Varies, see below.
		Type	        32-bit little-endian Signed Integer		Varies, see below.
		Body		    Null-terminated ASCII String			Varies, see below.
		Empty String    Null-terminated ASCII String			0x00
		*/

        //create packet
        $packet = pack('VV', $packetId, $packetType);
        $packet = $packet.$packetBody."\x00";
        $packet .= "\x00";

        // get packet size.
        $packet_size = strlen($packet);

        // attach size to packet.
        $packet = pack('V', $packet_size).$packet;

        // write packet.
        fwrite($this->socket, $packet, strlen($packet));
    }

    /**
     * Read a packet from the socket stream.
     *
     * @return array
     */
    private function readPacket() : array
    {
        //get packet size.
        $size_data = fread($this->socket, 4);
        $size_pack = unpack('V1size', $size_data);
        $size = $size_pack['size'];

        // if size is > 4096, the response will be in multiple packets.
        // this needs to be address. get more info about multi-packet responses
        // from the RCON protocol specification at
        // https://developer.valvesoftware.com/wiki/Source_RCON_Protocol
        // currently, this script does not support multi-packet responses.

        $packet_data = fread($this->socket, $size);

        return unpack('V1id/V1type/a*body', $packet_data);
        
    }
}
