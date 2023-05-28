ChatTGE
-----

**Description:** I tried to get the new crystal ball chat bot working, but it seems to have lost its marbles. Can you ask it to find the flag for me?

<url>
<handout.tar.gz>

Spoilers
-----

It's back! The Torque Game Engine web server that nobody asked for! Well, that's not true, fuzyll asked for _something_ and this is what he's getting: a WebSocket capable server written entirely in Torque Script, with JSON / SHA-1 / base64 implementations all lovingly hand rolled.

Bugs:
- eval() injection in jsonParse leads to arbitrary script execution (cc, MissionInfo)
- Buffer overflow in dSprintf leads to echo() smashing the stack (cc, macCarbStrings.cc)

The rest of the challenging aspect is just figuring out how to work around the scripting language and exploiting a stack smash under Wine.

Expected exploitation path:
- Check exe and find OpenMBU-Beta-1.15 in strings and download engine source from GitHub
- Use modified Untorque or similar to decompile dso scripts into source
- Analyze scripts and find eval() injection
- Write payload to enumerate server and find script sources
- Write payload to read script sources
- Find dSprintf overflow either through analyzing engine or fuzzing
- Use dSprintf overflow to get ROP
- Use ROP to get arbitrary execution
- Use arbitrary execution to read flag and send back

There are likely other solutions since it's a whole game engine from 2006 that is full of memory bugs. Considering dSprintf is used everywhere and doesn't bounds-check, most functions can give control of the stack. Those are generally everywhere, but people might find other holes in the engine would will certainly be interesting.