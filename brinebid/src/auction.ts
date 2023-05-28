import { super_constructor, format_currency, random_int } from "./lib/util.js";
import { PICKLE_GLOBAL_SCOPE } from "./lib/pickle/pickle-ops.js";
import { PythonObject } from "./lib/pickle/objects.js";
import { PickleWebsocket, Request, Response } from "./messages.ts";
import { get_current_balance, update_balance } from "./wallet.ts";
import { file_exists } from "./lib/util.js";
import { ROOT, AUCTION_LENGTH } from "./config.ts";

export async function get_current_auction() {
  try {
    let prop_index = await Deno.readTextFile(`${ROOT}/properties/auction/index.json`);
    prop_index = JSON.parse(prop_index);
    let current_time = Math.floor(+Date.now() / 1000 / AUCTION_LENGTH);
    let end_time = (current_time + 1) * AUCTION_LENGTH;

    let current_index = current_time % prop_index.length;
    let current_lot_name = prop_index[current_index];
    let current_lot = await Deno.readTextFile(`${ROOT}/properties/auction/${current_lot_name}`);
    current_lot = JSON.parse(current_lot);
    current_lot.end_time = end_time;

    let top = Number(BigInt('0x'+current_lot.secret) % 11n) / 10.0;
    let high_price = Math.floor(current_lot.sell_price * (1.5 + top));

    current_lot.description += ` Price range: < ${format_currency(high_price)}`;
    return current_lot;
  } catch (e) {
    console.error(e);
    return null;
  }
}

export async function get_old_bid() {
  try {
    const old_bid = await Deno.readTextFile(`${ROOT}/wallet/current_bid.json`);
    console.log('old_bid', old_bid);
    return JSON.parse(old_bid);
  } catch (e) {
    return null;
  }
}

export async function make_new_bid(uuid, val, tries) {
  try {
    let obj = {
      bid: val,
      uuid: uuid,
      count: tries,
    };
    let obj_j = JSON.stringify(obj);
    await Deno.writeTextFile(`${ROOT}/wallet/current_bid.json`, obj_j);
    return true;
  } catch (e) {
    console.error(e);
    return false;
  }
}

export async function copy_property(uuid) {
  try {
    await Deno.copyFile(`${ROOT}/properties/auction/${uuid}.token`, `${ROOT}/wallet/properties/${uuid}.token`);
    return true;
  } catch (e) {
    console.error(e);
    return false;
  }
}

// Make a bid for a house
export async function submit_bid(val) {
  val = ~~(val);
  if (isNaN(val) ||  val < 0 || val > 1000000000) {
    return [false, 'Sorry you did not get this property... Your bid is not valid.', null];
  }
  let balance = await get_current_balance();
  if (balance.sanddollars < val) {
    return [false, 'Sorry you did not get this property... You do not have enough money.', null];
  }

  let current_lot = await get_current_auction();
  let old_bid = await get_old_bid();
  let bid_tries = 0;
  if (old_bid && old_bid.uuid == current_lot.uuid) {
    bid_tries = old_bid.count;
    if (bid_tries >= 2) {
      return [false, 'Sorry you can only bid 2 times per property.', null];
    }
  }
  if (current_lot.floor_price > val) {
    bid_tries ++;
  } else {
    bid_tries = 100
  }

  if (!await make_new_bid(current_lot.uuid, val, bid_tries)) {
    return [false, 'Sorry you did not get this property... There was an error writing your bid.', null];
  }

  if (current_lot.floor_price > val) {
    if (bid_tries >= 2) {
      let min = current_lot.floor_price;
      let max = current_lot.sell_price;
      let winning_bid = Math.floor(Math.random() * (max - min + 1) + min);
      return [false, `Sorry you did not get this property... Your bid is too low. The property sold for ${format_currency(winning_bid)} SandDollars.\nTry again next time`, null];
    } else {
      return [false, `Sorry you did not get this property... Your bid is too low. You have ${2 - bid_tries} bid attempt left`, null];
    }
  }


  let new_balance = balance.sanddollars - val;

  if (!await update_balance({ sanddollars: new_balance })) {
    return [false, 'Sorry you did not get this property... There was an error updating your balance.', null];
  }


  if (!await copy_property(current_lot.uuid)) {
    return [false, 'Sorry you did not get this property... There was an error transfering the property to you.', null];
  }

  return [true, `Congratulations you bought the property for ${format_currency(val)} SandDollars! Estimated property value ~${format_currency(current_lot.sell_price)}`, current_lot];
}

export function AuctionProperty(args) /* extends PythonObject */ {
  var _this = this;
  _this = super_constructor(this, AuctionProperty, args);
  _this.uuid = args[0];
  _this.property_name = args[1];
  _this.description = args[2];
  _this.end_time = args[3];
  return _this;
}
// Inherit from class PythonObject
Object.setPrototypeOf(AuctionProperty.prototype, PythonObject.prototype);
PICKLE_GLOBAL_SCOPE['__main__.AuctionProperty'] = AuctionProperty;


export function PropertyToken(args) /* extends PythonObject */ {
  var _this = this;
  _this = super_constructor(this, PropertyToken, args);
  _this.uuid = args[0];
  _this.property_name = args[1];
  _this.description = args[2];
  _this.estimated_value = args[3];
  return _this;
}
// Inherit from class PythonObject
Object.setPrototypeOf(PropertyToken.prototype, PythonObject.prototype);
PICKLE_GLOBAL_SCOPE['__main__.PropertyToken'] = PropertyToken;


export function AuctionInfoRequest(args) /* extends Request */ {
  var _this = this;
  _this = super_constructor(this, AuctionInfoRequest, args);
  return _this;
}
// Inherit from class Request
Object.setPrototypeOf(AuctionInfoRequest.prototype, Request.prototype);
PICKLE_GLOBAL_SCOPE['__main__.AuctionInfoRequest'] = AuctionInfoRequest;

AuctionInfoRequest.prototype.process = async function (ws: PickleWebsocket) {
  const current_lot = await get_current_auction();
  let resp;
  if (current_lot) {
    resp = AuctionInfoResponse([
      current_lot.uuid,
      current_lot.name,
      current_lot.description,
      current_lot.end_time
    ]);
  } else {
    resp = AuctionInfoResponse([]);
  }
  resp.send(ws);
}



export function AuctionInfoResponse(args) /* extends Response */ {
  var _this = this;
  _this = super_constructor(this, AuctionInfoResponse, args);
  if (args.length > 0)
    _this.property = AuctionProperty(args);
  else
    _this.property = null;
  return _this;
}
// Inherit from class Response
Object.setPrototypeOf(AuctionInfoResponse.prototype, Response.prototype);
PICKLE_GLOBAL_SCOPE['__main__.AuctionInfoResponse'] = AuctionInfoResponse;



export function AuctionBidRequest(args) /* extends Request */ {
  var _this = this;
  _this = super_constructor(this, AuctionBidRequest, args);
  _this.bid = args[0];
  return _this;
}
// Inherit from class Request
Object.setPrototypeOf(AuctionBidRequest.prototype, Request.prototype);
PICKLE_GLOBAL_SCOPE['__main__.AuctionBidRequest'] = AuctionBidRequest;

AuctionBidRequest.prototype.process = async function (ws: PickleWebsocket) {
  let [res, msg, prop] = await submit_bid(this.bid);
  let resp;
  if (res) {
    resp = AuctionBidResponse([
      true, msg,
      prop.uuid,
      prop.name,
      prop.description,
      prop.sell_price,
    ]);
  } else {
    resp = AuctionBidResponse([false, msg]);
  }
  resp.send(ws);
}



export function AuctionBidResponse(args) /* extends Response */ {
  var _this = this;
  _this = super_constructor(this, AuctionBidResponse, args);
  _this.success = args[0];
  _this.message = args[1];
  if (args.length > 2)
    _this.property = AuctionProperty(args.slice(2));
  else
    _this.property = null;

  return _this;
}
// Inherit from class Response
Object.setPrototypeOf(AuctionBidResponse.prototype, Response.prototype);
PICKLE_GLOBAL_SCOPE['__main__.AuctionBidResponse'] = AuctionBidResponse;

export function auction_init() {}
