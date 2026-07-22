import { localErrorMessage, NativeOperationError } from "./native";

export function operationErrorMessage(error: unknown): string {
  if (error instanceof NativeOperationError) return localErrorMessage(error.code);
  return localErrorMessage("console_unavailable");
}
