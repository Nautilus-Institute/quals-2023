import { Buffer } from "../buffer-polyfill.js";
import { super_constructor } from "../util.js";
import { PICKLE_GLOBAL_SCOPE, PICKLE_OP_BYTES } from "./pickle-ops.js";
import { PythonObject } from "./objects.js";

export function Pickler(obj) /* extends PythonObject */ {
  var _this = this;
  _this = super_constructor(this, Pickler);
  _this.obj = obj;
  _this._pickle_impl();
  return _this;
}
// Inherit from class PythonObject
Object.setPrototypeOf(Pickler.prototype, PythonObject.prototype);
PICKLE_GLOBAL_SCOPE['pickle.Pickler'] = Pickler;

Pickler.prototype._pickle_impl = function() {
    var buf = Buffer.concat([
        O.PROTO,
        Buffer.from([3]),
        Pickler._pickle_value(this.obj),
        O.STOP
    ]);
    this.result = buf.toString('base64');
    console.log("pickled", this.result);
}

Pickler.pickle = function(obj) {
    console.log("pickling", obj);
    return new Pickler(obj).result;
}

var O = PICKLE_OP_BYTES;

function little_endian_uint32(n) {
    var b = Buffer.alloc(4);
    b.writeUInt32LE(n, 0);
    return b;
}


Pickler._pickle_value = function(v) {
    if (v === null || v === undefined) {
        return O.NONE;
    }
    if (typeof(v) == 'function') {
        return Buffer.from([]);
    }
    if (typeof(v) == 'number') {
        return Buffer.concat([
            O.LONG1,
            Buffer.from([4]),
            little_endian_uint32(v)
        ]);
    }
    if (typeof(v) == 'string') {
        if (v.length < 256) {
            return Buffer.concat([
                O.SHORT_BINSTRING,
                Buffer.from([v.length]),
                Buffer.from(v, 'utf8')
            ])
        }
        return Buffer.concat([
            O.BINSTRING,
            little_endian_uint32(v.length),
            Buffer.from(v, 'utf8')
        ])
    }
    return v.__pickle__();
}

Object.prototype.__pickle__ = function() {
    if (Array.isArray(this)) {
        return Array.prototype.__pickle__.call(this);
    }
    var out = [O.MARK];
    for (var k in this) {
        if (!this.hasOwnProperty(k)) {
            continue;
        }
        let kp = Pickler._pickle_value(k);
        if (kp.length == 0) {
            continue;
        }

        var v = this[k];
        var vp = Pickler._pickle_value(v);
        if (vp.length == 0) {
            continue;
        }

        out.push(kp);
        out.push(vp);
    }
    out.push(O.DICT);
    return Buffer.concat(out);
}

Array.prototype.__pickle__ = function() {
    var out = [O.MARK];
    for (var i = 0; i < this.length; i++) {
        var v = this[i];
        out.push(Pickler._pickle_value(v));
    }
    out.push(O.LIST);
    return Buffer.concat(out);
}

// Make using global class
PythonObject.prototype.__pickle__ = function() {
    var out = [O.GLOBAL];
    for (var k in PICKLE_GLOBAL_SCOPE) {
        var v = PICKLE_GLOBAL_SCOPE[k];
        if (v === this.constructor) {
            var namespace = k.split('.')[0];
            var name = k.split('.')[1];
            out.push(Buffer.from(namespace+'\n', 'utf8'));
            out.push(Buffer.from(name+'\n', 'utf8'));
            break;
        }
    }
    if (out.length == 1) {
        // Fallback to object pickle
        return Object.prototype.__pickle__.call(this, );
    }

    // Create empty instance
    out.push(O.EMPTY_TUPLE, O.NEWOBJ);

    let props = Object.prototype.__pickle__.call(this, );
    out.push(props);
    out.push(O.BUILD);

    return Buffer.concat(out);
}