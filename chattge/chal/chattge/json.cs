//-----------------------------------------------------------------------------
// JSON Operations
// Hand-rolled, as promised
// If you're reading this, you probably already found the bug
//-----------------------------------------------------------------------------

autoreload($Con::File);

function jsonParse(%json) {
   %len = strlen(%json);
   %result = jsonParseInternal(%json);
   if (getField(%result, 0) == -1) {
      return %result;
   }

   %pos = getField(%result, 0);
   devecho(%pos SPC getSubStr(%json, 0, %pos) @ "*"
      @ getSubStr(%json, %pos, %len));
   while (%pos < %len && isspace(%json, %pos)) {
      %pos ++;
      devecho(%pos SPC getSubStr(%json, 0, %pos) @ "*"
         @ getSubStr(%json, %pos, %len));
   }
   if (%pos != %len)
      return -1 TAB %pos;
   return %result;
}

function jsonParseInternal(%json) {
   %start = 0;
   %len = strlen(%json);
   while (isspace(%json, %start)) {
      %start ++;
   }
   %first = getSubStr(%json, %start, 1);
   switch$ (%first) {
      case "{": // Object
         %i = 0;
         %object = new ScriptObject() {};
         %pos = %start + 1;
         devecho(%pos SPC getSubStr(%json, 0, %pos) @ "*"
            @ getSubStr(%json, %pos, %len));
         while (%pos < %len) {
            while (%pos < %len && isspace(%json, %pos)) {
               %pos ++;
               devecho(%pos SPC getSubStr(%json, 0, %pos) @ "*"
                  @ getSubStr(%json, %pos, %len));
            }
            %name = jsonParseString(getSubStr(%json, %pos, %len), 0);
            if (getField(%name, 0) == -1) {
               %object.delete();
               return -1 TAB %pos;
            }
            %pos = %pos + getField(%name, 0);
            devecho(%pos SPC getSubStr(%json, 0, %pos) @ "*"
               @ getSubStr(%json, %pos, %len));
            %object.name[%i] = getField(%name, 1);
            while (%pos < %len && isspace(%json, %pos)) {
               %pos ++;
               devecho(%pos SPC getSubStr(%json, 0, %pos) @ "*"
                  @ getSubStr(%json, %pos, %len));
            }
            if (getSubStr(%json, %pos, 1) !$= ":") {
               %object.delete();
               return -1 TAB %pos;
            }
            %pos ++;
            devecho(%pos SPC getSubStr(%json, 0, %pos) @ "*"
               @ getSubStr(%json, %pos, %len));
            %item = jsonParseInternal(getSubStr(%json, %pos, %len));
            if (getField(%item, 0) == -1) {
               %object.delete();
               return -1 TAB %pos;
            }
            %pos = %pos + getField(%item, 0);
            devecho(%pos SPC getSubStr(%json, 0, %pos) @ "*"
               @ getSubStr(%json, %pos, %len));
            // Looks like this version of torque is too old for setFieldValue
            devecho(%object.getId() @ "." @ %object.name[%i] @ " = " @
                longstringify(getFields(%item, 1)) @ ";");
            eval(%object.getId() @ "." @ %object.name[%i] @ " = " @
               longstringify(getFields(%item, 1)) @ ";");
            while (%pos < %len && isspace(%json, %pos)) {
               %pos ++;
               devecho(%pos SPC getSubStr(%json, 0, %pos) @ "*"
                  @ getSubStr(%json, %pos, %len));
            }
            if (getSubStr(%json, %pos, 1) $= "}") {
               %pos ++;
               devecho(%pos SPC getSubStr(%json, 0, %pos) @ "*"
                  @ getSubStr(%json, %pos, %len));
               break;
            }
            if (getSubStr(%json, %pos, 1) !$= ",") {
               %object.delete();
               return -1 TAB %pos;
            }
            %pos ++;
            devecho(%pos SPC getSubStr(%json, 0, %pos) @ "*"
               @ getSubStr(%json, %pos, %len));
            %i ++;
         }
         return %pos TAB %object;
      case "[": // Array
         %i = 0;
         %array = new ScriptObject() { class = "Array"; };
         %pos = %start + 1;
         devecho(%pos SPC getSubStr(%json, 0, %pos) @ "*"
            @ getSubStr(%json, %pos, %len));
         while (%pos < %len) {
            %item = jsonParseInternal(getSubStr(%json, %pos, %len));
            if (getField(%item, 0) == -1) {
               %array.delete();
               return -1 TAB %pos;
            }
            %pos = %pos + getField(%item, 0);
            devecho(%pos SPC getSubStr(%json, 0, %pos) @ "*"
               @ getSubStr(%json, %pos, %len));
            %array.item[%i] = getFields(%item, 1);
            while (%pos < %len && isspace(%json, %pos)) {
               %pos ++;
               devecho(%pos SPC getSubStr(%json, 0, %pos) @ "*"
                  @ getSubStr(%json, %pos, %len));
            }
            if (getSubStr(%json, %pos, 1) $= "]") {
               %pos ++;
               devecho(%pos SPC getSubStr(%json, 0, %pos) @ "*"
                  @ getSubStr(%json, %pos, %len));
               break;
            }
            if (getSubStr(%json, %pos, 1) !$= ",") {
               %array.delete();
               return -1 TAB %pos;
            }
            %pos ++;
            devecho(%pos SPC getSubStr(%json, 0, %pos) @ "*"
               @ getSubStr(%json, %pos, %len));
            %i ++;
         }
         return %pos TAB %array;
      case "\"": // String
         return jsonParseString(%json, %start);
      case "0" or "1" or "2" or "3" or "4"
        or "5" or "6" or "7" or "8" or "9": // Number
         for (%pos = %start + 1; %pos < %len; %pos ++) {
            devecho(%pos SPC getSubStr(%json, 0, %pos) @ "*"
               @ getSubStr(%json, %pos, %len));
            if (strpos("0123456789", getSubStr(%json, %pos, 1)) == -1) {
               break;
            }
         }
         return %pos TAB getSubStr(%json, %start, %pos - %start);
      case "t": // true
         if (getSubStr(%json, %start, 4) $= "true") {
            return %start + 4 TAB true;
         }
      case "f": // false
         if (getSubStr(%json, %start, 5) $= "false") {
            return %start + 5 TAB false;
         }
      default:
   }
   return -1 TAB %start;
}

function jsonParseString(%json, %start) {
   %len = strlen(%json);
   if (getSubStr(%json, %start, 1) !$= "\"")
      return -1 TAB %start;
   for (%pos = %start + 1; %pos < %len; %pos ++) {
      devecho(%pos SPC getSubStr(%json, 0, %pos) @ "*"
         @ getSubStr(%json, %pos, %len));
      %ch = getSubStr(%json, %pos, 1);
      if (%ch $= "\\") {
         %pos ++;
         devecho(%pos SPC getSubStr(%json, 0, %pos) @ "*"
            @ getSubStr(%json, %pos, %len));
         continue;
      }
      if (%ch $= "\"") {
         break;
      }
   }
   if (getSubStr(%json, %pos, 1) !$= "\"")
      return -1 TAB %pos;
   %pos ++;
   devecho(%pos SPC getSubStr(%json, 0, %pos) @ "*"
      @ getSubStr(%json, %pos, %len));
   return %pos TAB collapseEscape(
      getSubStr(%json, %start + 1, %pos - %start - 2));
}

function jsonPrint(%object, %fancy) {
   if (!isObject(%object)) {
      if (%object $= "true" || %object $= "false") {
         return %object;
      }
      %len = strlen(%object);
      if (%len == 0) {
         return "\"\"";
      }
      for (%i = 0; %i < %len; %i ++) {
         if (strpos("0123456789", getSubStr(%object, %i, 1)) == -1) {
            // It's a string
            // Can't use expandEscape because single quotes
            %object = strreplace(%object, "\\", "\\\\");
            %object = strreplace(%object, "\r", "\\r");
            %object = strreplace(%object, "\n", "\\n");
            %object = strreplace(%object, "\"", "\\\"");
            return "\"" @ %object @ "\"";
         }
      }
      return %object;
   } else {
      if (%object.class $= "Array") {
         %result = "[";
         for (%i = 0; %object.item[%i] !$= ""; %i ++) {
            %child = jsonPrint(%object.item[%i], %fancy);
            devecho("child printed to " @ %child);
            if (%fancy) {
               %child = strreplace(%child, "\n", "\n   ");
            }
            if (%i > 0) {
               %result = %result @ ",";
            }
            if (%fancy) {
               %result = %result NL "   ";
            }
            %result = %result @ %child;
         }
         if (%fancy) {
            %result = %result @ "\n";
         }
         %result = %result @ "]";
         return %result;
      } else {
         %result = "{";
         for (%i = 0; %object.name[%i] !$= ""; %i ++) {
            // Too old for getFieldValue too
            devecho("return " @ %object @ "." @ %object.name[%i] @ ";");
            %value = eval("return " @ %object @ "." @ %object.name[%i] @ ";");
            %child = jsonPrint(%value, %fancy);
            devecho("child printed to " @ %child);
            if (%fancy) {
               %child = strreplace(%child, "\n", "\n   ");
            }
            if (%i > 0) {
               %result = %result @ ",";
            }
            if (%fancy) {
               %result = %result NL "   ";
            }
            %result = %result @ "\"" @ expandEscape(%object.name[%i]) @ "\":";
            if (%fancy) {
               %result = %result @ " ";
            }
            %result = %result @ %child;
         }
         if (%fancy) {
            %result = %result @ "\n";
         }
         %result = %result @ "}";
         return %result;
      }
   }
}

