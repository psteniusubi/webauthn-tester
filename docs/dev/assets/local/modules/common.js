export const invalidArgument = () => { throw new Error("invalid argument"); }
export const isNull = value => value === null || value === undefined;
export const notNull = value => value !== null && value !== undefined;
export const isEmpty = value => isNull(value) || value === "";
export const notEmpty = value => notNull(value) && value !== "";
export const isString = value => notNull(value) && (typeof value === "string");
export const isFunction = value => notNull(value) && (typeof value === "function");

export const assertNotNull = value => notNull(value) || invalidArgument();
export const assertString = value => isString(value) || invalidArgument();
export const assertFunction = value => isFunction(value) || invalidArgument();

export const ifNotNull = (value, func) => notNull(value) ? (notNull(func) && assertFunction(func) ? func(value) : value) : undefined;
export const ifNotEmpty = (value, func) => notEmpty(value) ? (notNull(func) && assertFunction(func) ? func(value) : value) : undefined;
