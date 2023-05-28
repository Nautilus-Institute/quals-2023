//-----------------------------------------------------------------------------
// ChatTGE
// Mod script that just loads the real scripts
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// Load up defaults console values.

$hostName = "";
$listenPort = 28080;

// Defaults console values
exec("./defaults.cs");

//-----------------------------------------------------------------------------
// Package overrides to initialize the mod.
package ChatTGE {

function displayHelp() {
   Parent::displayHelp();
   error(
      "Web Mod options:\n" @
      "  -listen <port>     Start by listening on <port>\n" @
      "  -host <name>       Only allow connections with Host <name>\n"
   );
}

function parseArgs() {
   Parent::parseArgs();

   // Arguments, which override everything else.
   for (%i = 1; %i < $Game::argc; %i ++) {
      %arg = $Game::argv[%i];
      %nextArg = $Game::argv[%i+1];
      %hasNextArg = $Game::argc - %i > 1;

      switch$ (%arg) {
      case "-listen":
         $argUsed[%i]++;
         if (%hasNextArg) {
            $listenPort = %nextArg;
            $argUsed[%i+1]++;
            %i++;
         } else {
            error("Error: Missing Command Line argument." SPC
               "Usage: -listen <port>");
         }
      case "-host":
         $argUsed[%i]++;
         if (%hasNextArg) {
            $hostName = %nextArg;
            $argUsed[%i+1]++;
            %i++;
         } else {
            error("Error: Missing Command Line argument." SPC
               "Usage: -host <name>");
         }
      }
   }
}

function onStart() {
   Parent::onStart();
   echo("\n--------- Initializing MOD: ChatTGE ---------");

   // Load the scripts that start it all...
   exec("./chat.cs");
   exec("./sha1.cs");
   exec("./json.cs");
   exec("./utils.cs");
   exec("./websocket.cs");

   enableWinConsole(true);

   startWebSocketServer($listenPort, $hostName);
}

function onExit() {
   Parent::onExit();
}

}; // Client package
activatePackage(ChatTGE);

// Debug assistance
function autoreload(%file) {
   %newCRC = getFileCRC(%file);
   if ($lastCRC[%file] !$= %newCRC) {
      $lastCRC[%file] = %newCRC;
      exec(%file);
      setModPaths(getModPaths());
   }
   cancel($autoloop[%file]);
   $autoloop[%file] = schedule(1000, 0, autoreload, %file);
}
