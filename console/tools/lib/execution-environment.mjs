import { isAbsolute } from "node:path";

const EXECUTION_ENVIRONMENT = "YOUR_CLOUD_EXECUTION_ENV";
const ALLOWED_ENVIRONMENTS = new Set(["ci", "lab"]);

export function requireIsolatedExecution(operation) {
  const declared = process.env[EXECUTION_ENVIRONMENT] ?? "";
  if (declared !== "" && !ALLOWED_ENVIRONMENTS.has(declared)) {
    throw new Error(
      `${EXECUTION_ENVIRONMENT} must be either "lab" or "ci"; received ${JSON.stringify(declared)}`,
    );
  }

  const githubRunner =
    process.env.CI === "true" &&
    process.env.GITHUB_ACTIONS === "true" &&
    isAbsolute(process.env.RUNNER_TEMP ?? "");

  if (githubRunner) {
    if (declared === "lab") {
      throw new Error(`${operation}: a GitHub runner cannot be declared as a LAB VM`);
    }
    return "ci";
  }

  if (declared === "ci") {
    throw new Error(
      `${operation}: CI execution requires the GitHub Actions runner markers and an absolute RUNNER_TEMP`,
    );
  }
  if (declared === "lab") return "lab";

  throw new Error(
    `${operation}: refusing execution on the development laptop; run in a LAB VM with ${EXECUTION_ENVIRONMENT}=lab or in GitHub Actions`,
  );
}
