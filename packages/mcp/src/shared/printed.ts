/** The symbol Node's `util.inspect`, and so `console.log`, calls to print a value. */
const inspectCustom = Symbol.for("nodejs.util.inspect.custom");

type Inspect = (value: unknown, options?: unknown) => string;

/**
 * Makes `util.inspect` and `console.log` print `value` as `name` followed by
 * every field except `secrets`. The hook is a non-enumerable property, so
 * JSON, object spread, and `Object.keys` do not see it. Returns `value`.
 */
export function omitWhenPrinted<T extends object>(value: T, name: string, secrets: readonly (keyof T & string)[]): T {
  Object.defineProperty(value, inspectCustom, {
    value(this: T, _depth: number, options: unknown, inspect?: Inspect): string {
      const fields = Object.fromEntries(
        Object.entries(this).filter(([key]) => !(secrets as readonly string[]).includes(key)),
      );
      return `${name} ${inspect ? inspect(fields, options) : JSON.stringify(fields)}`;
    },
  });
  return value;
}
