import { super_constructor } from "../util.js";
import { Memory } from "./memory.js";
import { PICKLE_GLOBAL_SCOPE } from "./pickle-ops.js";

export function List(args) /* extends Array */ {
  var _this = this;
  _this = super_constructor(this, List, ...args);
  return _this;
}
// Inherit from class Array
Object.setPrototypeOf(List.prototype, Array.prototype);
PICKLE_GLOBAL_SCOPE['builtins.list'] = List;



export function PythonObject(args) {
  var _this = this;
  _this = super_constructor(this, PythonObject, {});
  return _this;
}
// Inherit from class Memory 
Object.setPrototypeOf(PythonObject.prototype, Memory.prototype);
PICKLE_GLOBAL_SCOPE['builtins.Object'] = PythonObject;


export function Dict(args) /* extends PythonObject */ {
  var _this = this;
  _this = super_constructor(this, Dict, args);
  return _this;
}
// Inherit from class PythonObject
Object.setPrototypeOf(Dict.prototype, PythonObject.prototype);
PICKLE_GLOBAL_SCOPE['builtins.dict'] = Dict;



export function Exception(args) /* extends PythonObject */ {
  var _this = this;
  _this = super_constructor(this, Exception, args);
  return _this;
}
// Inherit from class PythonObject
Object.setPrototypeOf(Exception.prototype, PythonObject.prototype);
PICKLE_GLOBAL_SCOPE['builtins.Exception'] = Exception;