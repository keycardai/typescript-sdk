/** The symbol Node's `util.inspect`, and so `console.log`, calls to print a value. */
const inspectCustom = Symbol.for("nodejs.util.inspect.custom");

type Inspect = (value: unknown, options?: unknown) => string;

/**
 * Makes `util.inspect` and `console.log` print `value` as `name` followed by
 * `shown(value)`. The hook is a non-enumerable property, so JSON, object
 * spread, `Object.keys`, and Jest's `toEqual` do not see it. Returns `value`.
 */
export function setPrinted<T extends object>(value: T, name: string, shown: (value: T) => object): T {
  Object.defineProperty(value, inspectCustom, {
    value(this: T, _depth: number, options: unknown, inspect?: Inspect): string {
      const fields = shown(this);
      return `${name} ${inspect ? inspect(fields, options) : JSON.stringify(fields)}`;
    },
  });
  return value;
}
