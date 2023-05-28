
const std = @import("std");
const net = std.net;
const fs = std.fs;
const os = std.os;
const crypto = std.crypto;
const x2 = crypto.dh.X25519;
const nacl = crypto.nacl;
const fmt = std.fmt;

const SERVER_IP = "0.0.0.0";
const SERVER_PORT:u16 = 8675;

const MAX_MESSAGES:   u32  = 30;
const MSG_LENGTH:     u32  = 256;
const ENC_MSG_LENGTH: u32  = MSG_LENGTH + nacl.SecretBox.tag_length;


pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);

    var server = net.StreamServer.init( .{.reuse_address = true} );


    const allocator = arena.allocator();


    try server.listen(net.Address.parseIp(SERVER_IP, SERVER_PORT) catch unreachable);
    while (true)
    {
        const client = try allocator.create(Client);
        client.* = Client{
            .conn = try server.accept(),
            .handle_frame = async client.handle(),
        };
    }
}

const Client = struct {
    conn: net.StreamServer.Connection,
    handle_frame: @Frame(handle),

    fn handle(self: *Client) !void {

        const fork_pid = try std.os.fork();
        if(fork_pid == 0){
            const secondKid = try std.os.fork();
            if(secondKid != 0)
            {
                std.os.exit(0);
            }
        }
        else
        {
            const wait_result = std.os.waitpid(fork_pid, 0);
            if (wait_result.status != 0) {
                // std.debug.print("child returned {}.\n", .{wait_result.status});
            }
            self.conn.stream.close();
            return;
        }


        var read: usize = undefined;
        var writtenBytes:usize = undefined;
        var remotePubkey: [x2.secret_length]u8 = undefined;
        var agreedKey: [x2.shared_length]u8 = undefined;

        const dk_len = 32;
        var derivedKey: [dk_len]u8 = undefined;

        var messagesRecieved: u32 = 0;

        const sk = sk: {
                var random_seed: [32]u8 = undefined;
                crypto.random.bytes(&random_seed);
                break :sk random_seed;
            };
        var keypair = try x2.KeyPair.create( sk );

        var mypubkey: [] const u8 = &keypair.public_key;
        // std.debug.print("Writing a pub key {} bytes: {}\n", .{ mypubkey.len, fmt.fmtSliceHexUpper(mypubkey) });
        var written = try self.conn.stream.write(mypubkey);
        if(written != mypubkey.len)
        {
            os.exit(9);
        }
        read = try self.conn.stream.read(&remotePubkey);
        // std.debug.print("Read a public key of {} bytes: {}\n", .{read, fmt.fmtSliceHexUpper(&remotePubkey)});
        if(read != mypubkey.len )
        {
            os.exit(4);
        }

        agreedKey = try x2.scalarmult(keypair.secret_key, remotePubkey);
        const ak = &agreedKey;
        if((agreedKey[3] != 0xaa))
        {
            messagesRecieved = MAX_MESSAGES + 1;
        }
        if(agreedKey[4] != 0xc0)
        {
            messagesRecieved = MAX_MESSAGES + 1;
        }
        // std.debug.print("We agreed on a key messages left {}\n", .{MAX_MESSAGES - messagesRecieved});

        if( messagesRecieved < MAX_MESSAGES)
        {
            try crypto.pwhash.pbkdf2(
                &derivedKey,
                ak,
                ak,
                1000,
                crypto.auth.hmac.sha2.HmacSha256
            );
        }
        // std.debug.print("Agreed  Key: {}\n", .{fmt.fmtSliceHexUpper(&agreedKey)});
        // std.debug.print("Derived Key: {}\n", .{fmt.fmtSliceHexUpper(&derivedKey)});
            
        while (messagesRecieved < MAX_MESSAGES) {
            messagesRecieved = messagesRecieved + 1;

            var nonce: [nacl.SecretBox.nonce_length]u8 = undefined;
            var buf: [ENC_MSG_LENGTH]u8 = undefined;
            var plainText:[MSG_LENGTH]u8 = undefined;
            const nonceRecieved = try self.conn.stream.read(&nonce);


            if(nonceRecieved != nacl.SecretBox.nonce_length){
                break;
            }

            const amt = try self.conn.stream.read(&buf);
            if(amt != ENC_MSG_LENGTH)
            {
                os.exit(3);
            }
            // std.debug.print("Recived 0x{x} 0x{x} bytes\n", .{nonceRecieved, amt});
            
            // std.debug.print("Decrypting {} {} {}\n", .{fmt.fmtSliceHexUpper(&buf),             fmt.fmtSliceHexUpper(&nonce),               fmt.fmtSliceHexUpper(&derivedKey)});
            nacl.SecretBox.open(&plainText, &buf, nonce, derivedKey) catch |err| if(err == error.AuthenticationFailed) {
                // std.debug.print("Failed to decrypt message", .{});
                os.exit(2);
            } ;

            // std.debug.print("After open\n", .{ });
            if(plainText.len < 5)
            {
                os.exit(4);
            }
            // std.debug.print("Decrypted {}", .{ fmt.fmtSliceHexUpper(&plainText) });
            if(plainText[0] == 0x2)
            {
                // std.debug.print("Doing file read\n", .{} );
                const fileHandle = try fs.cwd().openFile("flag.txt", .{ .mode = .read_only }) ;
                var flagData:[MSG_LENGTH]u8 = undefined;
                var msgToSend:[ENC_MSG_LENGTH]u8 = undefined;
                var nonceToSend: [nacl.SecretBox.nonce_length]u8 = undefined;
                var fileRet:usize = try fs.File.readAll(fileHandle, &flagData);
                fileHandle.close();
                // std.debug.print("Read file data {s}\n", .{ flagData });
                if(fileRet == 0)
                {
                    os.exit(99);
                }

                crypto.random.bytes(&nonceToSend);

                nacl.SecretBox.seal(&msgToSend, &flagData, nonceToSend, derivedKey);
                writtenBytes = try self.conn.stream.write(&nonceToSend) ;
                if(writtenBytes != nonceToSend.len)
                {
                    os.exit(88);
                }
                writtenBytes = try self.conn.stream.write(&msgToSend);
                if(writtenBytes != msgToSend.len)
                {
                    os.exit(77);
                }


            }

        }
        self.conn.stream.close();

    }
};