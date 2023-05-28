import { super_constructor } from "../util.js";

export function Memory(state) {
  if (typeof(state) !== 'object') {
    state = {};
  }
  var _this = this;
  try {
    _this = super_constructor(this, Memory, state);
  } catch (e) {
    // Prod kept getting weird errors sometimes
    console.error();
    _this.assign(state);
  }
  return _this;
}
Memory.prototype.valueOf = function() {
  return Object.assign({}, this);
}
// Inherit from Object
Object.setPrototypeOf(Memory.prototype, Object);