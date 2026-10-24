// SPDX-License-Identifier: Apache-2.0
// Shared error type (kept in its own module so fhe.ts and torusdb.ts can both use it).

/**
 * Every failure surfaces as a TorusError. `kind` is the server's error class
 * (the text before the first ": " - e.g. "Unauthenticated", "Forbidden",
 * "Busy", "BadRequest", "InternalError", "PlanError") or one of the local
 * kinds: "ConnectionError" (cannot connect / connection lost / TLS failure),
 * "TimeoutError", "ProtocolError" (malformed or unsupported peer reply),
 * "InterfaceError" (client closed / misuse), "OutOfBudget" (value or
 * aggregate outside the exactly representable range), "IntegrityError" (a MAC
 * check failed: the server lied), "UntrustedSchema" (write to a table whose
 * encryption policies were only learned from the server) and
 * "TransactionInDoubt" (see {@link TransactionInDoubt}).
 */
export class TorusError extends Error {
  readonly kind: string;
  constructor(kind: string, message: string) {
    super(message);
    this.name = "TorusError";
    this.kind = kind;
    Object.setPrototypeOf(this, TorusError.prototype);
  }
}

