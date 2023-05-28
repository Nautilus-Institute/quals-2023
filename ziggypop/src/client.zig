
const std = @import("std");
const net = std.net;
const fs = std.fs;
const os = std.os;
const crypto = std.crypto;
const x2 = crypto.dh.X25519;
const nacl = crypto.nacl;
const fmt = std.fmt;
const tcp = std.net.tcp;


const SERVER_IP = "127.0.0.1";
const SERVER_PORT:u16 = 8675;

const MAX_MESSAGES:   u32  = 30;
const MSG_LENGTH:     u32  = 256;
const ENC_MSG_LENGTH: u32  = MSG_LENGTH + nacl.SecretBox.tag_length;


pub fn sendTicket(conn: std.net.Stream) !u32 {
    var data:[32]u8 = undefined;

    const bytesRec = try conn.read(&data) ;
    const ticketWrote = try conn.write("ticket{MessStarboard381n23:TDY2GFeOOuvZF8LGR2-zk7V2pBTiDdbUADgJbZf5f6vZLmNT}\n");
        
    if(bytesRec < 12)
    {
        std.debug.print("Got ticket request {s} \n", .{ data } ) ;
        return 0;
    }
    std.debug.print("Wrote ticket to remote \n", .{  });
    if(ticketWrote < 10)
    {
        std.debug.print("Failed to send ticket\n", .{} );
        return 0;
    }
    return 1;
}

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);


    const allocator = arena.allocator();

    const ip = std.os.getenv("ip").?;
    var data:[32]u8 = undefined;

    const conn = try net.tcpConnectToHost(allocator, ip, SERVER_PORT );


    const tickSent = try sendTicket(conn);
    if(tickSent == 0)
    {
        return;
    }

    std.time.sleep(10000000000);
    
    std.debug.print("Connection started {}\n", .{conn});
    const bytesRec = try conn.read(&data) ;
    if(bytesRec != 32)
    {
        std.debug.print("Didn't recieve public key, failed, bailing\n", .{} );
        os.exit(5);
    }

    std.debug.print("Read a public key of {} bytes: {}\n", .{ data.len, fmt.fmtSliceHexUpper(&data)});
    var finalKey: []u8 = undefined;
    while(bytesRec == 32)
    {
        const sk = sk: {
                var random_seed: [32]u8 = undefined;
                crypto.random.bytes(&random_seed);
                break :sk random_seed;
            };

        var keypair = try x2.KeyPair.create( sk );
        var agreedKey:[32]u8 = try x2.scalarmult(keypair.secret_key, data);

        if(agreedKey[3] == 0xaa)
        {
            finalKey = &agreedKey;
            if(agreedKey[4] == 0xc0)
            {
                const amountWritten = try conn.write(&keypair.public_key);
                std.debug.print("Sending public key {}: {}\n", .{keypair.public_key.len, fmt.fmtSliceHexUpper(&keypair.public_key)});
                std.debug.print("Agreed Key {}: {}\n", .{agreedKey.len, fmt.fmtSliceHexUpper(&agreedKey)});
                if(amountWritten != keypair.public_key.len)
                {
                    std.debug.print("Failed to write keylen bailing\n", .{});
                    os.exit(9);
                }
                break;
            }
        }
    }
    const dk_len = 32;
    var derivedKey: [dk_len]u8 = undefined;
    try crypto.pwhash.pbkdf2(
        &derivedKey,
        finalKey,
        finalKey,
        1000,
        crypto.auth.hmac.sha2.HmacSha256
    );
    std.debug.print("Derived Key {} : {}\n", .{ derivedKey.len, fmt.fmtSliceHexUpper(&derivedKey)});

    const input = [_]u8{0x02} ** 256 ;
    var ciphertext: [input.len + crypto.nacl.SecretBox.tag_length]u8 = undefined;
    const nonce:*[nacl.SecretBox.nonce_length]u8 = finalKey[0 .. nacl.SecretBox.nonce_length];
    nacl.SecretBox.seal(&ciphertext, &input, nonce.*, derivedKey);

    std.debug.print("Sending buffer {} {} \n", .{fmt.fmtSliceHexUpper(nonce), fmt.fmtSliceHexUpper(&ciphertext)});

    const nonceWritten = try conn.write(nonce);
    const cpWritten = try conn.write(&ciphertext);
    std.debug.print("Sent buffer {} {} bytes \n", .{nonceWritten, cpWritten});

    var toDecrypt: [ENC_MSG_LENGTH]u8 = undefined;
    var decrypted: [MSG_LENGTH]u8 = undefined;
    var sNonce:[nacl.SecretBox.nonce_length]u8 = undefined;

    const nonceLen = try conn.read(&sNonce);
    const decryptRec = try conn.read(&toDecrypt);
    std.debug.print("Bytes read {} {} \n", .{ nonceLen, decryptRec });
    try nacl.SecretBox.open(&decrypted, &toDecrypt, sNonce, derivedKey);
    std.debug.print(" Flag {s} \n", .{ decrypted });

}

