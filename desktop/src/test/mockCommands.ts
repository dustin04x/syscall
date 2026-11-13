import { invoke } from "@tauri-apps/api/core";
import { vi } from "vitest";

type Handler = unknown | ((args: Record<string, unknown> | undefined) => unknown);

export function mockCommands(handlers: Record<string, Handler>) {
  const mocked = vi.mocked(invoke);
  mocked.mockImplementation(((command: string, args?: Record<string, unknown>) => {
    const handler = handlers[command];
    if (handler === undefined) {
      return Promise.reject({
        code: "UNMOCKED_COMMAND",
        message: `No test handler for ${command}`
      });
    }
    try {
      return Promise.resolve(typeof handler === "function" ? handler(args) : handler);
    } catch (error) {
      return Promise.reject(error);
    }
  }) as typeof invoke);
  return mocked;
}
