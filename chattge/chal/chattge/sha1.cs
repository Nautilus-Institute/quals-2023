// I promise these are correct
// If you find yourself looking for bugs in SHA1,
// you've probably gone the wrong way.
// I really hope these are correct

//-----------------------------------------------------------------------------
// Oh no
//-----------------------------------------------------------------------------

autoreload($Con::File);

function b64encode(%str) {
   %bitCount = 0;
   %slen = strlen(%str);
   for (%i = 0; %i < %slen; %i += 2) {
      %ch = hex2dec(getSubStr(%str, %i, 2));

      %bit[%bitCount + 7] = (%ch & 1) >> 0;
      %bit[%bitCount + 6] = (%ch & 2) >> 1;
      %bit[%bitCount + 5] = (%ch & 4) >> 2;
      %bit[%bitCount + 4] = (%ch & 8) >> 3;
      %bit[%bitCount + 3] = (%ch & 16) >> 4;
      %bit[%bitCount + 2] = (%ch & 32) >> 5;
      %bit[%bitCount + 1] = (%ch & 64) >> 6;
      %bit[%bitCount + 0] = (%ch & 128) >> 7;
      %bitCount += 8;
   }
   %map = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
   %result = "";
   for (%i = 0; %i + 5 < %bitCount; %i += 6) {
      %idx = %bit[%i + 0] << 5
           | %bit[%i + 1] << 4
           | %bit[%i + 2] << 3
           | %bit[%i + 3] << 2
           | %bit[%i + 4] << 1
           | %bit[%i + 5] << 0;
      %result = %result @ getSubStr(%map, %idx, 1);
   }
   if (%bitCount - %i == 2) {
      %idx = %bit[%i + 0] << 5
           | %bit[%i + 1] << 4;
      %result = %result @ getSubStr(%map, %idx, 1) @ "==";
   }
   if (%bitCount - %i == 4) {
      %idx = %bit[%i + 0] << 5
           | %bit[%i + 1] << 4
           | %bit[%i + 2] << 3
           | %bit[%i + 3] << 2;
      %result = %result @ getSubStr(%map, %idx, 1) @ "=";
   }

   return %result;
}

//-----------------------------------------------------------------------------
// OH NO
//-----------------------------------------------------------------------------

function sha1(%str) {
   %byteCount = 0;
   %slen = strlen(%str);
   for (%i = 0; %i < %slen; %i ++) {
      %byte[%byteCount] = ord(getSubStr(%str, %i, 1)); %byteCount ++;
   }
   %byte[%byteCount] = 0x80; %byteCount ++;
   while (%byteCount % 64 != 56) {
      %byte[%byteCount] = 0x00; %byteCount ++;
   }
   // Torque ints are 32 bit so you will not get any more data
   %byte[%byteCount] = 0x00; %byteCount ++;
   %byte[%byteCount] = 0x00; %byteCount ++;
   %byte[%byteCount] = 0x00; %byteCount ++;
   %byte[%byteCount] = 0x00; %byteCount ++;
   %byte[%byteCount] = ((%slen << 3) & 0xFF000000) >> 24; %byteCount ++;
   %byte[%byteCount] = ((%slen << 3) & 0xFF0000) >> 16; %byteCount ++;
   %byte[%byteCount] = ((%slen << 3) & 0xFF00) >> 8; %byteCount ++;
   %byte[%byteCount] = (%slen << 3) & 0xFF; %byteCount ++;

   %h0 = 0x67452301;
   %h1 = 0xEFCDAB89;
   %h2 = 0x98BADCFE;
   %h3 = 0x10325476;
   %h4 = 0xC3D2E1F0;

   for (%chunk = 0; %chunk < %byteCount; %chunk += 64) {
      %a = %h0 ^ 0;
      %b = %h1 ^ 0;
      %c = %h2 ^ 0;
      %d = %h3 ^ 0;
      %e = %h4 ^ 0;

      for (%i = 0; %i < 16; %i ++) {
         %b0 = %byte[%chunk + %i * 4 + 0];
         %b1 = %byte[%chunk + %i * 4 + 1];
         %b2 = %byte[%chunk + %i * 4 + 2];
         %b3 = %byte[%chunk + %i * 4 + 3];
         %w[%i] = (%b0 << 24) | (%b1 << 16) | (%b2 << 8) | %b3;
      }

      for (%i = 16; %i < 80; %i ++) {
         %next = %w[%i - 3] ^ %w[%i - 8] ^ %w[%i - 14] ^ %w[%i - 16];
         %w[%i] = (%next << 1) | ((%next & 0x80000000) >> 31);
      }

      for (%i = 0; %i < 80; %i ++) {
         if (%i < 20) {
            %f = (%b & %c) ^ ((~%b) & %d);
            %k = 0x5A827999;
         } else if (%i < 40) {
            %f = %b ^ %c ^ %d;
            %k = 0x6ED9EBA1;
         } else if (%i < 60) {
            %f = (%b & %c) ^ (%b & %d) ^ (%c & %d);
            %k = 0x8F1BBCDC;
         } else if (%i < 80) {
            %f = %b ^ %c ^ %d;
            %k = 0xCA62C1D6;
         }

         %temp = (%a << 5) | ((%a & 0xF8000000) >> 27);

         // These are integer additions by the way
         %carry = %temp & %f;
         %result1 = %temp ^ %f;
         while (%carry !$= "0") {
            %shiftedCarry = %carry << 1;
            %carry = %result1 & %shiftedCarry;
            %result1 = %result1 ^ %shiftedCarry;
         }
         %carry = %result1 & %e;
         %result2 = %result1 ^ %e;
         while (%carry !$= "0") {
            %shiftedCarry = %carry << 1;
            %carry = %result2 & %shiftedCarry;
            %result2 = %result2 ^ %shiftedCarry;
         }
         %carry = %result2 & %k;
         %result3 = %result2 ^ %k;
         while (%carry !$= "0") {
            %shiftedCarry = %carry << 1;
            %carry = %result3 & %shiftedCarry;
            %result3 = %result3 ^ %shiftedCarry;
         }
         %carry = %result3 & %w[%i];
         %result4 = %result3 ^ %w[%i];
         while (%carry !$= "0") {
            %shiftedCarry = %carry << 1;
            %carry = %result4 & %shiftedCarry;
            %result4 = %result4 ^ %shiftedCarry;
         }

         %e = %d ^ 0;
         %d = %c ^ 0;
         %c = (%b << 30) | ((%b & 0xFFFFFFFC) >> 2);
         %b = %a ^ 0;
         %a = %result4 ^ 0;
      }

      %carry = %h0 & %a;
      %result = %h0 ^ %a;
      while (%carry !$= "0") {
         %shiftedCarry = %carry << 1;
         %carry = %result & %shiftedCarry;
         %result = %result ^ %shiftedCarry;
      }
      %h0 = %result ^ 0;

      %carry = %h1 & %b;
      %result = %h1 ^ %b;
      while (%carry !$= "0") {
         %shiftedCarry = %carry << 1;
         %carry = %result & %shiftedCarry;
         %result = %result ^ %shiftedCarry;
      }
      %h1 = %result ^ 0;

      %carry = %h2 & %c;
      %result = %h2 ^ %c;
      while (%carry !$= "0") {
         %shiftedCarry = %carry << 1;
         %carry = %result & %shiftedCarry;
         %result = %result ^ %shiftedCarry;
      }
      %h2 = %result ^ 0;

      %carry = %h3 & %d;
      %result = %h3 ^ %d;
      while (%carry !$= "0") {
         %shiftedCarry = %carry << 1;
         %carry = %result & %shiftedCarry;
         %result = %result ^ %shiftedCarry;
      }
      %h3 = %result ^ 0;

      %carry = %h4 & %e;
      %result = %h4 ^ %e;
      while (%carry !$= "0") {
         %shiftedCarry = %carry << 1;
         %carry = %result & %shiftedCarry;
         %result = %result ^ %shiftedCarry;
      }
      %h4 = %result ^ 0;
   }

   return dec2hex(%h0 >> 16, 4) @ dec2hex(%h0 & 0xFFFF, 4)
        @ dec2hex(%h1 >> 16, 4) @ dec2hex(%h1 & 0xFFFF, 4)
        @ dec2hex(%h2 >> 16, 4) @ dec2hex(%h2 & 0xFFFF, 4)
        @ dec2hex(%h3 >> 16, 4) @ dec2hex(%h3 & 0xFFFF, 4)
        @ dec2hex(%h4 >> 16, 4) @ dec2hex(%h4 & 0xFFFF, 4);
}
