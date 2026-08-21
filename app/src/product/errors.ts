import { localErrorMessage, NativeOperationError } from "./native";

export function operationErrorMessage(error: unknown): string {
  if (error instanceof NativeOperationError) return localErrorMessage(error.code);
  return localErrorMessage("app_unavailable");
}

/// Le contrôle qui a refusé, quand le cœur l’a nommé. Il se rend à côté de la
/// phrase, jamais à sa place : la phrase dit ce qu’un humain doit comprendre,
/// celle-ci dit à quoi s’en tenir quand la première ne suffit pas.
export function operationErrorDetail(error: unknown): string | null {
  return error instanceof NativeOperationError ? error.detail : null;
}
