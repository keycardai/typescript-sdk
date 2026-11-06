/**
 * JSON as eve journals it between durable steps. eve exported this type from
 * `eve/connections` through 0.83 and dropped it in 0.84; the shape is the
 * same on every release, so it lives here.
 */
export type JsonPrimitive = string | number | boolean | null;
export type JsonArray = readonly JsonValue[];
export type JsonObject = { readonly [key: string]: JsonValue };
export type JsonValue = JsonPrimitive | JsonArray | JsonObject;
