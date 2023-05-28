import { super_constructor } from "./lib/util.js";
import { WebSocketClient, WebSocketServer } from "https://deno.land/x/websocket@v0.1.4/mod.ts";
import { Exception } from "./lib/pickle/objects.js";
import { PICKLE_GLOBAL_SCOPE } from "./lib/pickle/pickle-ops.js";
import { HOST, PORT } from "./config.ts";
import { auction_init } from "./auction.ts";
import { file_exists } from "./lib/util.js";
import { PickleWebsocket, Request, Response } from "./messages.ts";
import { ROOT } from "./config.ts";

auction_init();

export function ResetRequest(args) /* extends Request */ {
    var _this = super_constructor(this, ResetRequest, args);
    return _this;
}
// Inherit from Request
ResetRequest.prototype = Object.create(Request.prototype);
PICKLE_GLOBAL_SCOPE['__main__.ResetRequest'] = ResetRequest;

ResetRequest.prototype.process = async function (ws : PickleWebsocket) {
  try {
      await Deno.remove(`${ROOT}/wallet/loans.json`);
  } catch (e) {}
  try {
      await Deno.remove(`${ROOT}/wallet/properties`, { recursive: true });
  } catch (e) {}
  try {
      await Deno.remove(`${ROOT}/wallet/balance.json`);
  } catch (e) {}

  init();
  ResetResponse([true, "Reset complete"]).send(ws);
}

export function ResetResponse(args) /* extends Response */ {
    var _this = super_constructor(this, ResetResponse, args);
    _this.success = args[0];
    _this.message = args[1];
    return _this;
}
// Inherit from Response
ResetResponse.prototype = Object.create(Response.prototype);
PICKLE_GLOBAL_SCOPE['__main__.ResetResponse'] = ResetResponse;



async function init() {
  if (!await file_exists(`${ROOT}/wallet/balance.json`)) {
    try {
      await Deno.mkdir(`${ROOT}/wallet`);
    } catch (e) {}
    try {
      await Deno.mkdir(`${ROOT}/wallet/properties`);
    } catch (e) {}
    await Deno.writeTextFile(`${ROOT}/wallet/loans.json`, '[]');
    await Deno.writeTextFile(`${ROOT}/wallet/balance.json`, '{"sanddollars":3500000}');
  }
}
await init();

window.wss = new WebSocketServer(PORT);
console.log('Listening on 8080...');
wss.on("connection", function (ws: WebSocketClient) {
  const pws = new PickleWebsocket(ws);
  window.current_client = pws;

  ws.on("message", function (message: string) {
    console.log(message);
    try {
      pws.process(message);
    } catch (e) {
      console.error(e)
      pws.send(Exception([e.toString()]));
    }
  });
});

