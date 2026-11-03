export const MAX_TEXT_BYTES: number;
export function encodeRecord(ciphertext: Uint8Array, signature: Uint8Array): string;
export function decodeRecord(text: string, maxBytes?: number): {ciphertext: Uint8Array; signature: Uint8Array};
export interface WasmStorage {
  openSignedStorageRecord(ciphertext: Uint8Array, signature: Uint8Array, secret: Uint8Array, namespace: Uint8Array, recordId: Uint8Array, version: bigint, writer: Uint8Array): Uint8Array;
}
export function openRecord(wasm: WasmStorage, text: string, secret: Uint8Array, namespace: Uint8Array, recordId: Uint8Array, expectedVersion: bigint, writer: Uint8Array): Uint8Array;
export interface TextStore {
  initialize(): Promise<void>;
  get(storageKey: string, expectedVersion: bigint): Promise<string | null>;
  compareAndSwap(storageKey: string, previousVersion: bigint | null, text: string): Promise<boolean>;
}
export interface LibsqlClient {
  execute(statement: {sql: string; args: string[]}): Promise<{rows: ArrayLike<unknown>; rowsAffected: number}>;
}
export interface MysqlConnection {
  execute(sql: string, args: string[]): Promise<[unknown, unknown]>;
}
export function tursoStore(client: LibsqlClient, options?: {maxBytes?: number}): TextStore;
export function hyperdriveStore(connection: MysqlConnection, options?: {maxBytes?: number}): TextStore;
