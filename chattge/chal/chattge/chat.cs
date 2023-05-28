//-----------------------------------------------------------------------------
// Crystal (8) ball chat bot service
//-----------------------------------------------------------------------------

autoreload($Con::File);

function Chat::onConnect(%socket) {
   echo("Connected: " @ %socket.address);
}

function Chat::onMessage(%socket, %message) {
   %parsed = jsonParse(%message);
   if (getField(%parsed, 0) == -1) {
      %error = "Parse error: "
         @ getSubStr(%message, 0, getFields(%parsed, 1))
         @ "-->"
         @ getSubStr(%message, getFields(%parsed, 1), strlen(%message));
      %message = new ScriptObject() {
         name[0] = "type";
         name[1] = "value";
         type = "stderr";
         value = %error;
      };
      %response = %socket.message(jsonPrint(%message));
      %message.delete();
      return;
   }

   %message = getFields(%parsed, 1);
   if (%message.type $= "message") {
      devecho(">> " @ %message.value);
      %value = getRandom(0, 19);
      switch (%value) {
         case 0: %result = "It is certain";
         case 1: %result = "It is decidedly so";
         case 2: %result = "Without a doubt";
         case 3: %result = "Yes definitely";
         case 4: %result = "You may rely on it";
         case 5: %result = "As I see it, yes";
         case 6: %result = "Most likely";
         case 7: %result = "Outlook good";
         case 8: %result = "Yes";
         case 9: %result = "Signs point to yes";
         case 10: %result = "Reply hazy try again";
         case 11: %result = "Ask again later";
         case 12: %result = "Better not tell you now";
         case 13: %result = "Cannot predict now";
         case 14: %result = "Concentrate and ask again";
         case 15: %result = "Don't count on it";
         case 16: %result = "My reply is no";
         case 17: %result = "My sources say no";
         case 18: %result = "Outlook not so good";
         case 19: %result = "Very doubtful";
      }
   } else if (%message.type $= "calculator") {
      %result = "No, I said we're not doing the stupid calculator thing.";
   } else if (%message.type $= "PQ") {
      %result = "WHERe"; // greetz IRD
   } else {
      %result = "I don't know what you mean by " @ %message.type @ ".";
   }

   %message = new ScriptObject() {
      name[0] = "type";
      name[1] = "value";
      type = "result";
      value = %result;
   };
   %socket.message(jsonPrint(%message));
   %message.delete();
}

function Chat::onDisconnect(%socket) {
   echo("Disconnected: " @ %socket.address);
}
