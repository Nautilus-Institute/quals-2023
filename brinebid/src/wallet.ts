import { random_int, super_constructor, format_currency } from "./lib/util.js";
import { PICKLE_GLOBAL_SCOPE } from "./lib/pickle/pickle-ops.js";
import { PythonObject } from "./lib/pickle/objects.js";
import { PickleWebsocket, Request, Response } from "./messages.ts";
import { file_exists } from "./lib/util.js";
import { ROOT } from "./config.ts";
import { PropertyToken } from "./auction.ts";
import { get_loans } from "./loan.ts";

export async function get_current_balance() {
  try {
    const current_lot = await Deno.readTextFile(`${ROOT}/wallet/balance.json`);
    console.log(current_lot);
    return JSON.parse(current_lot);
  } catch (e) {
    console.error(e);
    throw e;
    return { sanddollars: 0 };
  }
}
export async function update_balance(val) {
  try {
    val = JSON.stringify(val);
    await Deno.writeTextFile(`${ROOT}/wallet/balance.json`, val);
    return true;
  } catch (e) {
    return false;
  }
}

export async function get_owned_properties() {
  try {
    console.log("get_owned_properties");
    const ents = await Deno.readDir(`${ROOT}/wallet/properties/`);
    console.log(ents);
    let props: any[] = [];
    for await (const ent of ents) {
      console.log("==============", ent);
      const prop = await Deno.readTextFile(`${ROOT}/wallet/properties/${ent.name}`);
      let prop_obj;
      try {
          prop_obj = JSON.parse(prop);
      } catch (e) {
          return Error(`Invalid property file: ${prop}`);
      }

      props.push(prop_obj);
    }
    return props;
  } catch (e) {
    console.error(e);
    return [];
  }
}


export async function get_net_worth() {
  let balance = await get_current_balance();
  let properties = await get_owned_properties();
  let loans = await get_loans();

  let net_worth = balance.sanddollars;
  for (let prop of properties) {
    net_worth += prop.sell_price;
  }
  for (let loan of loans) {
    net_worth -= loan.with_intrest;
  }
  return {
    net_worth,
    balance: balance.sanddollars,
    properties,
    loans,
  }
}



export function Wallet(args) /* extends PythonObject */ {
  var _this = this;
  _this = super_constructor(this, Wallet, args);
  _this.balance = args[0];
  _this.properties = args[1];
  _this.loans = args[2];
  _this.netWorth = args[3];
  return _this;
}
// Inherit from class PythonObject
Object.setPrototypeOf(Wallet.prototype, PythonObject.prototype);
PICKLE_GLOBAL_SCOPE['__main__.Wallet'] = Wallet;



export function WalletRequest(args) /* extends Request */ {
  var _this = this;
  _this = super_constructor(this, WalletRequest, args);
  return _this;
}
// Inherit from class Request
Object.setPrototypeOf(WalletRequest.prototype, Request.prototype);
PICKLE_GLOBAL_SCOPE['__main__.WalletRequest'] = WalletRequest;

WalletRequest.prototype.process = async function (ws: PickleWebsocket) {
    const info = await get_net_worth();
    const res = WalletResponse([
        info.balance,
        info.properties.map((prop) => PropertyToken([
            prop.uuid,
            prop.name,
            prop.description,
            prop.sell_price,
            prop.image,
        ])),
        info.loans,
        info.net_worth
    ]);
    res.send(ws);
}



export function WalletResponse(args) /* extends Response */ {
  var _this = this;
  _this = super_constructor(this, WalletResponse, args);
  _this.wallet = Wallet(args);
  return _this;
}
// Inherit from class Response
Object.setPrototypeOf(WalletResponse.prototype, Response.prototype);
PICKLE_GLOBAL_SCOPE['__main__.WalletResponse'] = WalletResponse;



export function SellPropertyRequest(args) /* extends Request */ {
  var _this = this;
  _this = super_constructor(this, SellPropertyRequest, args);
  _this.uuid = args[0];
  return _this;
}
// Inherit from class Request
Object.setPrototypeOf(SellPropertyRequest.prototype, Request.prototype);
PICKLE_GLOBAL_SCOPE['__main__.SellPropertyRequest'] = SellPropertyRequest;

SellPropertyRequest.prototype.process = async function (ws: PickleWebsocket) {
  let properties = await get_owned_properties();
  if (properties instanceof Error) {
    SellPropertyResponse([false, `Failed to get properties: ${properties}`, 0]).send(ws);
    return;
  }
  let uuid = this.uuid;
  let target_prop = null;
  let index = 0;
  for (let prop of properties) {
    if (prop.uuid == uuid) {
      target_prop = prop;
      break;
    }
    index ++;
  }

  if (!target_prop) {
    SellPropertyResponse([false, "Property not found", 0]).send(ws);
    return;
  }

  let range = random_int(0, Math.floor(target_prop.sell_price * .05));
  range = range * (Math.random() > .33 ? 1 : -1);
  let sale_price = target_prop.sell_price + Math.floor(range);

  properties.splice(index, 1);
  let file_path = `${ROOT}/wallet/properties/${target_prop.uuid}.token`;
  try {
    //console.warn("Removing", file_path);
    await Deno.remove(file_path);
  } catch (e) {
    console.error(e);
    SellPropertyResponse([false, "Failed to remove property", 0]).send(ws);
    return;
  }

  let balance = await get_current_balance();
  balance.sanddollars += sale_price;
  if (!await update_balance(balance)) {
    SellPropertyResponse([false, "Failed to update balance", 0]).send(ws);
    return;
  }

  SellPropertyResponse([true, `Property successfully sold for ${format_currency(sale_price)}`, sale_price]).send(ws);
}


export function SellPropertyResponse(args) /* extends Response */ {
  var _this = this;
  _this = super_constructor(this, SellPropertyResponse, args);
  _this.success = args[0];
  _this.message = args[1];
  _this.sale_price = args[2];
  return _this;
}
// Inherit from class Response
Object.setPrototypeOf(SellPropertyResponse.prototype, Response.prototype);
PICKLE_GLOBAL_SCOPE['__main__.SellPropertyResponse'] = SellPropertyResponse;
