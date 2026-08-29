// Hand-rolled JSON Schema validator (M1 D2).
// Supports only the subset our schemas use: type, required, properties,
// items, enum, const, minimum/maximum, minLength/maxLength, pattern.
// AJV runs in the test suite as the authoritative cross-check.

import { schemaError, type ExplorerError } from './errors.js';

export type JsonType =
  | 'string'
  | 'number'
  | 'integer'
  | 'boolean'
  | 'object'
  | 'array'
  | 'null';

export interface Schema {
  type?: JsonType | JsonType[];
  required?: string[];
  properties?: Record<string, Schema>;
  additionalProperties?: boolean | Schema;
  items?: Schema;
  enum?: readonly unknown[];
  const?: unknown;
  minimum?: number;
  maximum?: number;
  exclusiveMinimum?: number;
  exclusiveMaximum?: number;
  minLength?: number;
  maxLength?: number;
  pattern?: string;
}

export interface ValidationResult {
  valid: boolean;
  errors: ExplorerError[];
}

function typeOf(v: unknown): JsonType {
  if (v === null) return 'null';
  if (Array.isArray(v)) return 'array';
  const t = typeof v;
  if (t === 'number') return Number.isInteger(v) ? 'integer' : 'number';
  if (t === 'object') return 'object';
  if (t === 'string' || t === 'boolean') return t;
  throw new Error(`unsupported JS type: ${t}`);
}

function typeMatches(actual: JsonType, expected: JsonType | JsonType[]): boolean {
  const allowed = Array.isArray(expected) ? expected : [expected];
  for (const e of allowed) {
    if (e === actual) return true;
    // number accepts integer
    if (e === 'number' && actual === 'integer') return true;
  }
  return false;
}

function validateInto(
  value: unknown,
  schema: Schema,
  path: string,
  errors: ExplorerError[],
): void {
  if (schema.const !== undefined) {
    if (value !== schema.const) {
      errors.push(
        schemaError(path, `expected const ${JSON.stringify(schema.const)}`, value),
      );
      return;
    }
  }

  if (schema.enum !== undefined) {
    if (!schema.enum.includes(value)) {
      errors.push(schemaError(path, `value not in enum`, value));
      return;
    }
  }

  if (schema.type !== undefined) {
    const actual = typeOf(value);
    if (!typeMatches(actual, schema.type)) {
      errors.push(
        schemaError(
          path,
          `expected ${Array.isArray(schema.type) ? schema.type.join('|') : schema.type}, got ${actual}`,
          value,
        ),
      );
      return;
    }
  }

  if (typeof value === 'number') {
    if (schema.minimum !== undefined && value < schema.minimum) {
      errors.push(schemaError(path, `< minimum ${schema.minimum}`, value));
    }
    if (schema.maximum !== undefined && value > schema.maximum) {
      errors.push(schemaError(path, `> maximum ${schema.maximum}`, value));
    }
    if (schema.exclusiveMinimum !== undefined && value <= schema.exclusiveMinimum) {
      errors.push(schemaError(path, `<= exclusiveMinimum ${schema.exclusiveMinimum}`, value));
    }
    if (schema.exclusiveMaximum !== undefined && value >= schema.exclusiveMaximum) {
      errors.push(schemaError(path, `>= exclusiveMaximum ${schema.exclusiveMaximum}`, value));
    }
  }

  if (typeof value === 'string') {
    if (schema.minLength !== undefined && value.length < schema.minLength) {
      errors.push(schemaError(path, `string too short`, value));
    }
    if (schema.maxLength !== undefined && value.length > schema.maxLength) {
      errors.push(schemaError(path, `string too long`, value));
    }
    if (schema.pattern !== undefined) {
      const re = new RegExp(schema.pattern);
      if (!re.test(value)) {
        errors.push(schemaError(path, `string fails pattern ${schema.pattern}`, value));
      }
    }
  }

  if (Array.isArray(value) && schema.items !== undefined) {
    for (let i = 0; i < value.length; i++) {
      validateInto(value[i], schema.items, `${path}[${i}]`, errors);
    }
  }

  if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
    const obj = value as Record<string, unknown>;
    if (schema.required !== undefined) {
      for (const key of schema.required) {
        if (!(key in obj)) {
          errors.push(schemaError(`${path}.${key}`, 'required key missing'));
        }
      }
    }
    if (schema.properties !== undefined) {
      for (const [key, sub] of Object.entries(schema.properties)) {
        if (key in obj) {
          validateInto(obj[key], sub, `${path}.${key}`, errors);
        }
      }
    }
    if (schema.additionalProperties === false && schema.properties !== undefined) {
      for (const key of Object.keys(obj)) {
        if (!(key in schema.properties)) {
          errors.push(schemaError(`${path}.${key}`, 'additional property not allowed'));
        }
      }
    } else if (
      typeof schema.additionalProperties === 'object' &&
      schema.additionalProperties !== null &&
      schema.properties !== undefined
    ) {
      for (const key of Object.keys(obj)) {
        if (!(key in schema.properties)) {
          validateInto(obj[key], schema.additionalProperties, `${path}.${key}`, errors);
        }
      }
    }
  }
}

export function validate(value: unknown, schema: Schema, rootPath = '$'): ValidationResult {
  const errors: ExplorerError[] = [];
  validateInto(value, schema, rootPath, errors);
  return { valid: errors.length === 0, errors };
}
