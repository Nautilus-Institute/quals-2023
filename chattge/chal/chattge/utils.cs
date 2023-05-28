//-----------------------------------------------------------------------------
// Utility Functions
//-----------------------------------------------------------------------------

autoreload($Con::File);

function dec2hex(%val, %pad) {
   if (%pad $= "")
      %pad = 1;
   %digits = "0123456789ABCDEF";
   %result = "";
   while (%val !$= "0") {
      %digit = getSubStr(%digits, %val & 0xF, 1);
      %result = %digit @ %result;
      %val = %val >> 4;
   }

   while (strlen(%result) < %pad)
      %result = "0" @ %result;
   return %result;
}

function hex2dec(%val) {
   %digits = "0123456789ABCDEF";
   %result = 0;
   while (%val !$= "") {
      %result <<= 4;
      %digit = getSubStr(%val, 0, 1);
      %result |= strPos(%digits, %digit);
      %val = getSubStr(%val, 1, strlen(%val));
   }
   return %result;
}

// http://www.garagegames.com/community/blogs/view/10202
// RIP garagegames.com
function URLDecode(%rawString) {
   // Encode strings from HTTP safe for URL use

   // If the string we are encoding has text... start encoding
   if (strlen(%rawString) > 0) {
      // Loop through each character in the string
      for (%i = 0; %i < strlen(%rawString); %i ++) {
         // Grab the character at our current index location
         %chrTemp = getSubStr(%rawString, %i, 1);

         if (%chrTemp $= "+") {
            // Was it a "+" symbol?  Change it to a space
            %chrTemp = " ";
         }
         //  If the character was not valid for an HTTP URL... Decode it
         if (%chrTemp $= "%") {
            //Get the dec value for the character
            %chrTemp = chr(hex2dec(getSubStr(%rawString, %i + 1, 2)));
            %i += 2;
         }
         // Build our encoded string
         %encodeString = %encodeString @ %chrTemp;
      }
   }
   // Return the encoded string value
   return %encodeString;
}

// With regards to spy47
function devecho(%text) {
   if ($devmode) {
      %blockSize = 1024;
      for (%j = 0; %j < strlen(%text); %j += %blockSize) {
         echo(getSubStr(%text, %j, %blockSize));
      }
   }
}

function longstringify(%value) {
   %result = "";
   %blockSize = 1000;
   for (%j = 0; %j < strlen(%value); %j += %blockSize) {
      if (%j > 0) {
         %result = %result @ "@";
      }
      // Get bent, Torque lexer
      %result = %result @ "\"" @ expandEscape(
         getSubStr(%value, %j, %blockSize)) @ "\"";
   }
   if (%result $= "") {
      return "\"\"";
   }
   return %result;
}

//-----------------------------------------------------------------------------
// Goddamnit
//-----------------------------------------------------------------------------

deactivatePackage(FixExpandEscape);
package FixExpandEscape {
   function expandEscape(%str) {
      %result = "";

      // This char, and only this char, does not expand properly
      %pos = strpos(%str, "\xFF");
      while (%pos != -1) {
         %result = %result @ Parent::expandEscape(getSubStr(%str, 0, %pos))
            @ "\\xFF";
         %str = getSubStr(%str, %pos + 1, strlen(%str));
         %pos = strpos(%str, "\xFF");
      }
      %result = %result @ Parent::expandEscape(%str);

      return %result;
   }
};
activatePackage(FixExpandEscape);

// Master crafted high performance shit that should have been built-in

// int -> char
function chr(%i) {
   if (%i == 0) {
      error("Cannot chr(0)!");
      return "";
   }
   return getSubStr(
           " \x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
      @ "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
      @ "\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f"
      @ "\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f"
      @ "\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f"
      @ "\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f"
      @ "\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f"
      @ "\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f"
      @ "\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f"
      @ "\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f"
      @ "\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf"
      @ "\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf"
      @ "\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf"
      @ "\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf"
      @ "\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef"
      @ "\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff",
      %i, 1);
}

// char -> int
function ord(%ch) {
   return strpos(
            "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
      @ "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
      @ "\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f"
      @ "\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f"
      @ "\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f"
      @ "\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f"
      @ "\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f"
      @ "\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f"
      @ "\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f"
      @ "\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f"
      @ "\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf"
      @ "\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf"
      @ "\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf"
      @ "\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf"
      @ "\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef"
      @ "\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff",
      %ch) + 1;
}
