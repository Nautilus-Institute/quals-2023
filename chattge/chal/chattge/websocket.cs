//-----------------------------------------------------------------------------
// TCPObject WebSocket Server!
// It's back, baby!
// glenns
//
// "what a strange question...not sure why you'd ask that? but, 8" -fuzyll
//-----------------------------------------------------------------------------

autoreload($Con::File);

//-----------------------------------------------------------------------------
// Constants
//-----------------------------------------------------------------------------

$HTTP::ResponseCode[100] = "Continue";
$HTTP::ResponseCode[101] = "Switching Protocols";
$HTTP::ResponseCode[200] = "OK";
$HTTP::ResponseCode[201] = "Created";
$HTTP::ResponseCode[202] = "Accepted";
$HTTP::ResponseCode[203] = "Non-Authoritative Information";
$HTTP::ResponseCode[204] = "No Content";
$HTTP::ResponseCode[205] = "Reset Content";
$HTTP::ResponseCode[206] = "Partial Content";
$HTTP::ResponseCode[300] = "Multiple Choices";
$HTTP::ResponseCode[301] = "Moved Permanently";
$HTTP::ResponseCode[302] = "Found";
$HTTP::ResponseCode[303] = "See Other";
$HTTP::ResponseCode[304] = "Not Modified";
$HTTP::ResponseCode[305] = "Use Proxy";
$HTTP::ResponseCode[307] = "Temporary Redirect";
$HTTP::ResponseCode[400] = "Bad Request";
$HTTP::ResponseCode[401] = "Unauthorized";
$HTTP::ResponseCode[402] = "Payment Required";
$HTTP::ResponseCode[403] = "Forbidden";
$HTTP::ResponseCode[404] = "Not Found";
$HTTP::ResponseCode[405] = "Method Not Allowed";
$HTTP::ResponseCode[406] = "Not Acceptable";
$HTTP::ResponseCode[407] = "Proxy Authentication Required";
$HTTP::ResponseCode[408] = "Request Timeout";
$HTTP::ResponseCode[409] = "Conflict";
$HTTP::ResponseCode[410] = "Gone";
$HTTP::ResponseCode[411] = "Length Required";
$HTTP::ResponseCode[412] = "Precondition Failed";
$HTTP::ResponseCode[413] = "Request Entity Too Large";
$HTTP::ResponseCode[414] = "Request-URI Too Long";
$HTTP::ResponseCode[415] = "Unsupported Media Type";
$HTTP::ResponseCode[416] = "Requested Range Not Satisfiable";
$HTTP::ResponseCode[417] = "Expectation Failed";
$HTCPCP::ResponseCode[418] = "I'm a teapot"; // RFC 2324
$HTTP::ResponseCode[500] = "Internal Server Error";
$HTTP::ResponseCode[501] = "Not Implemented";
$HTTP::ResponseCode[502] = "Bad Gateway";
$HTTP::ResponseCode[503] = "Service Unavailable";
$HTTP::ResponseCode[504] = "Gateway Timeout";
$HTTP::ResponseCode[505] = "HTTP Version Not Supported";

$WebSocket::Opcode["Continuation"] = 0;
$WebSocket::Opcode["Text"] = 1;
$WebSocket::Opcode["Binary"] = 2;
$WebSocket::Opcode["Close"] = 8;
$WebSocket::Opcode["Ping"] = 9;
$WebSocket::Opcode["Pong"] = 10;

//-----------------------------------------------------------------------------
// Server
//-----------------------------------------------------------------------------

function startWebSocketServer(%port, %hostName) {
   new TCPObject(WebSocketServer);
   echo("Starting WebSocket Server on " @ %port @ ":" @ %port
      @ " with host name " @ %hostName);
   WebSocketServer.hostName = %hostName;
   WebSocketServer.port = %port;
   WebSocketServer.listen(%port);
   RootGroup.add(WebSocketServer.clients = new SimSet(WebSocketServerClients));
   // Torque is stupid in that ConsoleLogger doesn't create a file entry for
   // the log it is writing, so we need to create one by hand.
   %fo = new FileObject();
   %fo.openForWrite("chattge/websocket.log");
   %fo.close();
   %fo.delete();
}

function WebSocketServer::onConnectRequest(%this, %address, %fd) {
   devecho("WebSocketServer::onConnectRequest(" @ %this @ ", " @ %address
      @ ", " @ %fd @ ")");
   // Gotta admit I forgot constructors could have arguments...
   // Quick scan of the engine source shows that literally only TCPObjects and
   // ConsoleLoggers use constructor arguments.
   %connection = new TCPObject(WebSocketServerClient, %fd);
   %connection.server = %this;
   %connection.address = %address;
   %connection.init();
   WebSocketServer.clients.add(%connection);
}

//-----------------------------------------------------------------------------
// Connection Management
//-----------------------------------------------------------------------------

function WebSocketServerClient::init(%this) {
   %this.state = "REQUEST";
   %this.uri = "";
   %this.headers = 0;
   %this.requestLine = "";

   for (%i = 0; %i < %this.receivedHeaders; %i ++) {
      %this.receivedHeader[%this.receivedHeader[%i, "name"]] = "";
      %this.receivedHeader[%i, "name"] = "";
      %this.receivedHeader[%i, "value"] = "";
   }
   %this.receivedHeaders = 0;
   %this.addHeader("Server", getVersionString() @
      " ChatTGE/0.2 " @ $platform);
}

function WebSocketServerClient::onLine(%this, %line) {
   switch$ (%this.state) {
      case "REQUEST":
         devecho("WebSocketServerClient::onLine(" @ %this @ ", " @ %line @ ")");
         %this.requestLine = %line;
         %this.state = "HEADER";
      case "HEADER":
         devecho("WebSocketServerClient::onLine(" @ %this @ ", " @ %line @ ")");
         if (%line !$= "") {
            %this.receivedHeader[%this.receivedHeaders] = %line;
            %this.receivedHeaders ++;
         } else {
            %this.processHeaders();
            %this.upgrade();
         }
      case "CONNECTED":
         // Unmask and handle data
         %this.connectedLine(%line @ "\n");
   }
}

function WebSocketServerClient::upgrade(%this) {
   if (%this.method !$= "GET") {
      devecho("Not GET");
      %this.responseCode = 400;
      %this.abort();
      return;
   }
   if (%this.receivedHeader["Host"] $= "") {
      devecho("Missing Host");
      %this.responseCode = 400;
      %this.abort();
      return;
   }
   if (%this.server.hostName !$= ""
      && %this.receivedHeader["Host"] !$= %this.server.hostName) {
      devecho("Bad Host");
      %this.responseCode = 404;
      %this.abort();
      return;
   }
   if (%this.uri $= "/") {
      %this.responseCode = 500;

      %conts = "";
      %file = new FileObject();
      if (%file.openForRead("chattge/index.html")) {
         %this.responseCode = 200;
         for (%line = %file.readLine(); !%file.isEOF();
            %line = %file.readLine()) {
            %conts = %conts @ %line @ "\n";
         }
      }
      %file.delete();
      %this.addHeader("Content-Length", strlen(%conts));
      %this.addHeader("Connection", "Close");
      %this.sendHeaders();
      %this.send(%conts);
      %this.init();
      return;
   }
   if (strpos(strlwr(%this.receivedHeader["Upgrade"]), "websocket") == -1) {
      devecho("Missing/bad Upgrade");
      %this.responseCode = 400;
      %this.abort();
      return;
   }
   if (strpos(strlwr(%this.receivedHeader["Connection"]), "upgrade") == -1) {
      devecho("Missing/bad Connection");
      %this.responseCode = 400;
      %this.abort();
      return;
   }
   if (%this.receivedHeader["Sec-WebSocket-Key"] $= "") {
      devecho("Missing Sec-WebSocket-Key");
      %this.responseCode = 400;
      %this.abort();
      return;
   }
   if (%this.receivedHeader["Sec-WebSocket-Version"] !$= "13") {
      devecho("Missing/bad Sec-WebSocket-Version");
      %this.responseCode = 400;
      %this.abort();
      return;
   }

   // Prepare opening handshake
   %this.responseCode = 101;

   %this.addHeader("Upgrade", "websocket");
   %this.addHeader("Connection", "Upgrade");
   %this.addHeader("WebSocket-Origin", %this.receivedHeader["Host"]);
   %this.addHeader("WebSocket-Location", "ws://" @ %this.receivedHeader["Host"]
      @ ":" @ %this.port @ %this.uri);
   %this.addHeader("Sec-WebSocket-Accept",
      b64encode(sha1(%this.receivedHeader["Sec-WebSocket-Key"]
         @ "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")));
   // No Sec-WebSocket-Protocol
   // No Sec-WebSocket-Extensions

   %this.sendHeaders();
   %this.state = "CONNECTED";

   %this.sendHeartbeat();

   %this.wrapOutput("Chat::onConnect", %this);
}

//-----------------------------------------------------------------------------
// Data Transfer
//-----------------------------------------------------------------------------

function WebSocketServerClient::sendHeaders(%this) {
   if ($HTTP::ResponseCode[%this.responseCode] $= "") {
      %this.responseCode = 405;
   }

   %message = "HTTP/1.1" SPC %this.responseCode SPC
      $HTTP::ResponseCode[%this.responseCode];
   for (%i = 0; %i < %this.headers; %i ++) {
      %message = %message @ "\r\n" @ %this.header[%i, "name"] @ ":" SPC
         %this.header[%i, "value"];
   }
   %message = %message @ "\r\n";
   %message = %message @ "\r\n";
   %r = %this.send(%message);
   if (%r < 0) {
      // TODO: Handle
      error("Send error: " @ %r);
   }
}

function WebSocketServerClient::connectedLine(%this, %line) {
   %this.buffer = %this.buffer @ %line;
   %this.bufferLen += strlen(%line);

   %frame = %this.parseFrame();
   while (isObject(%frame)) {
      %this.onFrame(%frame);
      %frame.delete();
      %frame = %this.parseFrame();
   }
}

function WebSocketServerClient::parseFrame(%this) {
   %pos = 0;
   if (%this.bufferLen <= %pos) return "";
   %b0 = ord(getSubStr(%this.buffer, %pos, 1)); %pos ++;
   if (%this.bufferLen <= %pos) return "";
   %b1 = ord(getSubStr(%this.buffer, %pos, 1)); %pos ++;
   if (%this.bufferLen <= %pos) return "";

   %fin = (%b0 & 0x80) == 0x80;
   %opcode = %b0 & 0xF;
   %mask = (%b1 & 0x80) == 0x80;
   %length = (%b1 & 0x7F);
   if (%length == 126) {
      %length = (ord(getSubStr(%this.buffer, %pos, 1)) << 8)
              | ord(getSubStr(%this.buffer, 3, 1));
      %pos += 2;
      if (%this.bufferLen <= %pos) return "";
   } else if (%length == 127) {
      %length = (ord(getSubStr(%this.buffer, %pos + 4, 1)) << 24)
              | (ord(getSubStr(%this.buffer, %pos + 5, 1)) << 16)
              | (ord(getSubStr(%this.buffer, %pos + 6, 1)) << 8)
              | (ord(getSubStr(%this.buffer, %pos + 7, 1)) << 0);
      %pos += 8;
      if (%this.bufferLen <= %pos) return "";
   }
   // LOL floats
   if (getSubStr(%length, 0, 1) $= "-") {
      %this.close(1011, "Null byte detected");
      return "";
   }
   if (%mask) {
      %key = getSubStr(%this.buffer, %pos, 4); %pos += 4;
      if (%this.bufferLen <= %pos) return "";
   } else {
      %key = "";
   }
   %buffer = getSubStr(%this.buffer, %pos, %length);
   %pos += %length;
   if (%this.bufferLen <= %pos) return "";

   %this.buffer = getSubStr(%this.buffer, %pos, %this.bufferLen);
   %this.bufferLen -= %pos;

   if (%mask) {
      // Unmask buffer
      %raw = "";
      %unmasked = "";
      for (%i = 0; %i < %length; %i ++) {
         %raw = %raw @ dec2hex(ord(getSubStr(%buffer, %i, 1)), 2);
         %ch = ord(getSubStr(%buffer, %i, 1))
             ^ ord(getSubStr(%key, %i % 4, 1));
         if (%ch == 0) {
            // We've desynced real badly somewhere
            %this.close(1011, "Null byte detected");
            return "";
         }
         %unmasked = %unmasked @ chr(%ch);
      }
      %buffer = %unmasked;
   }

   %frame = new ScriptObject() {
      fin = %fin;
      opcode = %opcode;
      length = %length;
      buffer = %buffer;
      raw = %raw;
      mask = %mask;
      key = %key;
   };
   return %frame;
}

function WebSocketServerClient::onFrame(%this, %frame) {
   switch (%frame.opcode) {
      case 0: // Continuation
         %this.message = %this.message @ %frame.buffer;
         if (%frame.fin) {
            // Finish frame
            %this.onMessage(%this.message);
            %this.message = "";
         }
      case 1: // Text
         %this.message = %frame.buffer;
         if (%frame.fin) {
            // Finish frame
            %this.onMessage(%this.message);
            %this.message = "";
         }
      case 2: // Binary
         %this.message = %frame.buffer;
         if (%frame.fin) {
            // Finish frame
            %this.onMessage(%this.message);
            %this.message = "";
         }
      case 3 or 4 or 5 or 6 or 7: // Reserved
      case 8: // Connection close
         %this.close(1000, "Connection closed by peer");
      case 9: // Ping
         %this.pong(%frame.buffer);
      case 10: // Pong
         // Don't care
      case 11 or 12 or 13 or 14 or 15: // Reserved
   }
}

function WebSocketServerClient::wrapOutput(%this, %func, %arg1, %arg2) {
   if ($devmode) {
      %logFile =  "chattge/websocket.log";
      %logger = new ConsoleLogger(HTTPLogger, %logFile);
      %logger.attach();
      %logger.level = warning;
   }

   devecho("return " @ %func @ "(" @ longstringify(%arg1) @ ", "
      @ longstringify(%arg2) @ ");");
   %result = eval("return " @ %func @ "(" @ longstringify(%arg1) @ ", "
      @ longstringify(%arg2) @ ");");

   if ($devmode) {
      %logger.detach();
      %logger.delete();

      // Collect errors
      %file = new FileObject();
      if (%file.openForRead(%logFile)) {
         for (%line = %file.readLine(); %line !$= "";
            %line = %file.readLine()) {
            %message = new ScriptObject() {
               name[0] = "type";
               name[1] = "value";
               type = "stdout";
               value = %line;
            };
            %this.message(jsonPrint(%message));
            %message.delete();
         }
         %file.close();
      } else {
         %message = new ScriptObject() {
            name[0] = "type";
            name[1] = "value";
            type = "stdout";
            value = "Cannot open file " @ %logFile;
         };
         %this.message(jsonPrint(%message));
         %message.delete();
      }
      %file.delete();
   }

   return %result;
}

function WebSocketServerClient::onMessage(%this, %message) {
   %this.wrapOutput("Chat::onMessage", %this, %message);
}

function WebSocketServerClient::sendFrame(%this, %buffer, %fin, %op, %mask) {
   %b0 = $WebSocket::Opcode[%op];
   if (%fin) {
      %b0 |= 0x80;
   }
   %packet = chr(%b0);

   %b1 = 0;
   if (%mask) {
      %b1 |= 0x80;
   }
   %length = strlen(%buffer);
   if (%length > 65535) {
      return false;
   } else if (%length > 125) {
      if (%length < 255) {
         return false;
      }
      if (%length % 256 == 0) {
         return false;
      }
      %b1 |= 126;
      %packet = %packet
         @ chr(%b1)
         @ chr((%length & 0xFF00) >> 8)
         @ chr(%length & 0xFF);
   } else {
      %b1 |= %length;
      %packet = %packet @ chr(%b1);
   }
   if (%mask) {
      // Pick something that won't make the buffer have any zeros
      for (%i = 0; %i < %length; %i += 4) {
         %chr0 = ord(getSubStr(%buffer, %i + 0, 1));
         %chr1 = ord(getSubStr(%buffer, %i + 1, 1));
         %chr2 = ord(getSubStr(%buffer, %i + 2, 1));
         %chr3 = ord(getSubStr(%buffer, %i + 3, 1));

         %used0[%chr0] = true;
         %used1[%chr1] = true;
         %used2[%chr2] = true;
         %used3[%chr3] = true;
      }

      %found = false;
      for (%i = 1; %i < 256; %i ++) {
         if (!%used0[%i]) {
            %key = %key @ chr(%i);
            %found = true;
            break;
         }
      }
      if (!%found) {
         return false;
      }

      %found = false;
      for (%i = 1; %i < 256; %i ++) {
         if (!%used1[%i]) {
            %key = %key @ chr(%i);
            %found = true;
            break;
         }
      }
      if (!%found) {
         return false;
      }

      %found = false;
      for (%i = 1; %i < 256; %i ++) {
         if (!%used2[%i]) {
            %key = %key @ chr(%i);
            %found = true;
            break;
         }
      }
      if (!%found) {
         return false;
      }

      %found = false;
      for (%i = 1; %i < 256; %i ++) {
         if (!%used3[%i]) {
            %key = %key @ chr(%i);
            %found = true;
            break;
         }
      }
      if (!%found) {
         return false;
      }

      %masked = "";
      for (%i = 0; %i < %length; %i ++) {
         %ch = ord(getSubStr(%buffer, %i, 1)) ^ ord(getSubStr(%key, %i % 4, 1));
         if (%ch == 0) {
            // Should never happen
            %this.close(1011, "Null byte detected");
            return "";
         }
         %masked = %masked @ chr(%ch);
      }
      %buffer = %masked;

      %packet = %packet @ %key;
   }
   %packet = %packet @ %buffer;
   %r = %this.send(%packet);
   if (%r < 0) {
      return false;
   }
   return true;
}

function WebSocketServerClient::message(%this, %buffer) {
   devecho("<< " @ %buffer);
   %length = strlen(%buffer);
   for (%i = 0; %i < %length; %i += 125) {
      %chunk = getSubStr(%buffer, %i, 125);

      %first = %i == 0;
      %last = %i + 125 >= %length;

      %op = (%first ? "Text" : "Continuation");
      %fin = %last;

      if (!%this.sendFrame(%chunk, %fin, %op, false)) {
         %this.close(1006, "Failed to send frame");
         return false;
      }
   }
   return true;
}

function WebSocketServerClient::ping(%this, %buffer) {
   if (!%this.sendFrame(%buffer, true, "Ping", false)) {
      %this.close(1006, "Failed to send frame");
      return false;
   }
   return true;
}

function WebSocketServerClient::pong(%this, %buffer) {
   if (!%this.sendFrame(%buffer, true, "Pong", false)) {
      %this.close(1006, "Failed to send frame");
      return false;
   }
   return true;
}

function WebSocketServerClient::close(%this, %code, %reason) {
   %this.wrapOutput("Chat::onDisconnect", %this, %reason);
   %buffer = chr(%code >> 8) @ chr(%code & 0xFF) @ %reason;
   %this.sendFrame(%buffer, true, "Close", false);
   %this.init();
}

function WebSocketServerClient::abort(%this) {
   %this.sendHeaders();
   %this.init();
}

function WebSocketServerClient::sendHeartbeat(%this) {
   cancel(%this.heartbeat);
   if (!%this.ping("Workaround for TCPObject::onLine")) {
      return;
   }
   %this.heartbeat = %this.schedule(200, sendHeartbeat);
}

//-----------------------------------------------------------------------------
// Utilities
//-----------------------------------------------------------------------------

function WebSocketServerClient::addHeader(%this, %name, %value) {
   %this.header[%this.headers, "name"] = %name;
   %this.header[%this.headers, "value"] = %value;
   %this.headers ++;
}

function WebSocketServerClient::processHeaders(%this) {
   %method  = getWord(%this.requestLine, 0);
   %uri     = getWord(%this.requestLine, 1);
   %version = getWord(%this.requestLine, 2);

   if (getSubStr(%version, 0, 7) !$= "HTTP/1.") {
      %this.responseCode = 505;
      %this.abort();
      return;
   }

   %this.method = %method;
   %this.uri = %uri;

   for (%i = 0; %i < %this.receivedHeaders; %i ++) {
      %header = %this.receivedHeader[%i];
      %colon = strpos(%header, ":");
      if (%colon == -1) {
         %this.responseCode = 400;
         %this.abort();
         return;
      }
      %name = trim(getSubStr(%header, 0, %colon));
      %value = trim(getSubStr(%header, %colon + 1, strlen(%header)));
      %this.receivedHeader[%i, "name"] = %name;
      %this.receivedHeader[%i, "value"] = %value;
      %this.receivedHeader[%name] = %value;
   }
}

function WebSocketServerClient::parseQuery(%this, %query) {
   %this.params = 0;
   %amp = strpos(%query, "&");
   while (%amp != -1) {
      %param = getSubStr(%query, 0, %amp);
      %equals = strpos(%param, "=");
      if (%equals == -1) {
         return false;
      }
      %name = getSubStr(%param, 0, %equals);
      %value = getSubStr(%param, %equals + 1, strlen(%param));

      %this.param[%this.params, "name"] = URLDecode(%name);
      %this.param[%this.params, "value"] = URLDecode(%value);
      %this.params ++;

      %query = getSubStr(%query, %amp + 1, strlen(%query));
      %amp = strpos(%query, "&");
   }
   %param = %query;
   if (%param $= "") {
      return true;
   }
   %equals = strpos(%param, "=");
   if (%equals == -1) {
      return false;
   }
   %name = getSubStr(%param, 0, %equals);
   %value = getSubStr(%param, %equals + 1, strlen(%param));

   %this.param[%this.params, "name"] = URLDecode(%name);
   %this.param[%this.params, "value"] = URLDecode(%value);
   %this.params ++;

   return true;
}
