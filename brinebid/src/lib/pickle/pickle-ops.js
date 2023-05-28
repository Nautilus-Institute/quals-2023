import { Buffer } from '../buffer-polyfill.js';
export var PICKLE_OP_NAMES = {
  MARK: '(',
  STOP: '.',
  POP: '0',
  POP_MARK: '1',
  DUP: '2',
  FLOAT: 'F',
  INT: 'I',
  BININT: 'J',
  BININT1: 'K',
  LONG: 'L',
  BININT2: 'M',
  NONE: 'N',
  PERSID: 'P',
  BINPERSID: 'Q',
  REDUCE: 'R',
  STRING: 'S',
  BINSTRING: 'T',
  SHORT_BINSTRING: 'U',
  UNICODE: 'V',
  BINUNICODE: 'X',
  APPEND: 'a',
  BUILD: 'b',
  GLOBAL: 'c',
  DICT: 'd',
  EMPTY_DICT: '}',
  APPENDS: 'e',
  GET: 'g',
  BINGET: 'h',
  INST: 'i',
  LONG_BINGET: 'j',
  LIST: 'l',
  EMPTY_LIST: ']',
  OBJ: 'o',
  PUT: 'p',
  BINPUT: 'q',
  LONG_BINPUT: 'r',
  SETITEM: 's',
  TUPLE: 't',
  EMPTY_TUPLE: ')',
  SETITEMS: 'u',
  PROTO: '\x80',
  NEWOBJ: '\x81',
  TUPLE1: '\x85',
  TUPLE2: '\x86',
  TUPLE3: '\x87',
  NEWTRUE: '\x88',
  NEWFALSE: '\x89',
  LONG1: '\x8a',
  LONG4: '\x8b',
  BINBYTES: 'B',
  SHORT_BINBYTES: 'C',
};

export var PICKLE_OP_VALUES = {};
for (var k in PICKLE_OP_NAMES) {
  PICKLE_OP_VALUES[PICKLE_OP_NAMES[k]] = k;
}

export var PICKLE_OP_BYTES = {};
for (var k in PICKLE_OP_NAMES) {
  let v = PICKLE_OP_NAMES[k].charCodeAt(0);
  PICKLE_OP_BYTES[k] = Buffer.from([v]);
}

export var PICKLE_GLOBAL_SCOPE = {};