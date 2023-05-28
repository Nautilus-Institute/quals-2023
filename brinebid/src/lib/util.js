// Automatically call the class's super constructor if it exists
export function super_constructor(_this, clazz, ...args) {
  if (!clazz.prototype) return _this;

  if (!_this) {
    _this = Object.create(clazz.prototype);
  }

  let super_class = Object.getPrototypeOf(clazz.prototype);
  if (!super_class || !super_class.constructor) return _this;

  var res;
  // Call super class constructor
  res = super_class.constructor.call(_this, ...args);
  if (res && res !== _this) {
    Object.setPrototypeOf(res, clazz.prototype);
    return res;
  }
  return _this;
}

export async function file_exists(filename) {
  try {
    await Deno.stat(filename);
    return true;
  } catch (error) {
    if (error instanceof Deno.errors.NotFound) {
      return false;
    } else {
      throw error;
    }
  }
};

export function random_int(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

export function format_currency(val) {
  return '$'+val.toFixed(2).replace(/\d(?=(\d{3})+\.)/g, '$&,').slice(0,-3);
}