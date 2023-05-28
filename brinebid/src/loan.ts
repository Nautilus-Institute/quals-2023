import { super_constructor, random_int, format_currency } from "./lib/util.js";
import { PICKLE_GLOBAL_SCOPE } from "./lib/pickle/pickle-ops.js";
import { PythonObject } from "./lib/pickle/objects.js";
import { PickleWebsocket, Request, Response } from "./messages.ts";
import { get_current_balance, update_balance } from "./wallet.ts";
import { file_exists } from "./lib/util.js";
import { ROOT } from "./config.ts";

export async function get_loans() {
  try {
    let loans = await Deno.readTextFile(`${ROOT}/wallet/loans.json`);
    loans = JSON.parse(loans);
    for (let loan of loans) {
      // Calculate compound interest
      let time_since = Date.now() - loan.time;
      let periods = time_since / (60.0 * 60.0);
      let n = 60.0;
      let rate = loan.rate;
      loan.with_intrest = loan.amount * Math.pow(1 + rate / n, n * periods);
    }
    return loans;
  } catch (e) {
    return [];
  }
}

export async function set_loans(loans) {
    try {
        loans = JSON.stringify(loans);
        await Deno.writeTextFile(`${ROOT}/wallet/loans.json`, loans);
        return true;
    } catch (e) {
        return false;
    }
}


export function NewLoanRequest(args) /* extends Request */ {
    var _this = super_constructor(this, NewLoanRequest, args);
    return _this;
}
// Inherit from Request
NewLoanRequest.prototype = Object.create(Request.prototype);
PICKLE_GLOBAL_SCOPE['__main__.NewLoanRequest'] = NewLoanRequest;

NewLoanRequest.prototype.process = async function (ws : PickleWebsocket) {
    let loans = await get_loans();
    let balance = await get_current_balance();

    let val = random_int(1_000_000, 10_000_000);
    val = Math.floor(val / 1000) * 1000;
    let rate = 0.0005 - .000001 * random_int(0,200);
    let loan = {
        amount: val,
        rate: rate,
        time: Math.floor(+Date.now()),
    };
    loans.push(loan);
    if (!await set_loans(loans)) {
        NewLoanResponse([false, "Failed to create loan", 0]).send(ws);
    }
    balance.sanddollars += val;
    if (!await update_balance(balance)) {
        NewLoanResponse([false, "Failed to update balance", 0]).send(ws);
    }

    NewLoanResponse([true, `You received a loan of ${format_currency(loan.amount)}`, loan.amount]).send(ws);
}

export function NewLoanResponse(args) /* extends Response */ {
    var _this = super_constructor(this, NewLoanResponse, args);
    _this.success = args[0];
    _this.message = args[1];
    _this.value = args[2];
    return _this;
}
// Inherit from Response
NewLoanResponse.prototype = Object.create(Response.prototype);
PICKLE_GLOBAL_SCOPE['__main__.NewLoanResponse'] = NewLoanResponse;



export function PayLoanRequest(args) /* extends Request */ {
    var _this = super_constructor(this, PayLoanRequest, args);
    _this.loan_index = args[0];
    return _this;
}
// Inherit from Request
PayLoanRequest.prototype = Object.create(Request.prototype);
PICKLE_GLOBAL_SCOPE['__main__.PayLoanRequest'] = PayLoanRequest;

PayLoanRequest.prototype.process = async function (ws : PickleWebsocket) {
    let loans = await get_loans();
    let balance = await get_current_balance();
    let indx = this.loan_index;
    if (indx < 0 || indx >= loans.length) {
        PayLoanResponse([false, "Invalid loan index"]).send(ws);
        return;
    }

    let loan = loans[indx];
    if (loan.with_intrest > balance.sanddollars) {
        PayLoanResponse([false, "Insufficient funds"]).send(ws);
        return;
    }

    balance.sanddollars -= loan.with_intrest;
    if (!await update_balance(balance)) {
        PayLoanResponse([false, "Failed to update balance"]).send(ws);
        return;
    }

    loans.splice(indx, 1);
    if (!await set_loans(loans)) {
        PayLoanResponse([false, "Failed to update loans"]).send(ws);
        return;
    }

    PayLoanResponse([true, "Loan paid"]).send(ws);
}

export function PayLoanResponse(args) /* extends Response */ {
    var _this = super_constructor(this, PayLoanResponse, args);
    _this.success = args[0];
    _this.message = args[1];
    return _this;
}
// Inherit from Response
PayLoanResponse.prototype = Object.create(Response.prototype);
PICKLE_GLOBAL_SCOPE['__main__.PayLoanResponse'] = PayLoanResponse;

