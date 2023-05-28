import { super_constructor } from "./lib/util.js";
import { PICKLE_GLOBAL_SCOPE } from "./lib/pickle/pickle-ops.js";
import { PythonObject } from "./lib/pickle/objects.js";
import { Pickler } from "./lib/pickle/pickle.js";
import { Unpickler } from "./lib/pickle/unpickle.js";
import { WebSocketClient } from "https://deno.land/x/websocket@v0.1.4/mod.ts";
import { Exception } from "./lib/pickle/objects.js";

export class PickleWebsocket {
  constructor(ws : WebSocketClient) {
    this.ws = ws;
  }
  send(obj) {
    const out = Pickler.pickle(obj);
    this.ws.send(out);
  }
  process(message) {
    let struct = Unpickler.unpickle(message, 'base64');
    if (struct instanceof Message) {
      struct = struct.body;

    }
    if (struct instanceof Request) {
      struct.process(this);
    } else {
      this.send(Exception(["Invalid request"]));
    }
  }

  ws : WebSocketClient;
}



/* == Pickle objects == */

export function Message(args) /* extends PythonObject */ {
  var _this = super_constructor(this, Message, args);
  _this.sender = args[0];
  _this.body = args[1];
  return _this;
}
// Inherit from class PythonObject
Object.setPrototypeOf(Message.prototype, PythonObject.prototype);
PICKLE_GLOBAL_SCOPE['__main__.Message'] = Message;



export function Request(args) /* extends PythonObject */ {
  var _this = super_constructor(this, Request, args);
  return _this;
}
// Inherit from class PythonObject
Object.setPrototypeOf(Request.prototype, PythonObject.prototype);
PICKLE_GLOBAL_SCOPE['__main__.Request'] = Request;

Request.prototype.process = function (ws : PickleWebsocket) {
  ws.send(Exception(["Not implemented"]));
}



export function Response(args) /* extends PythonObject */ {
  var _this = super_constructor(this, Response, args);
  return _this;
}
// Inherit from class PythonObject
Object.setPrototypeOf(Response.prototype, PythonObject.prototype);
PICKLE_GLOBAL_SCOPE['__main__.Response'] = Response;

Response.prototype.send = function (pws : PickleWebsocket) {
  pws.send(Message(['server',this]));
}
