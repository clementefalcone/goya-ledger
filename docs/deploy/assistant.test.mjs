import { test } from "node:test";
import assert from "node:assert/strict";
import { STEPS, ROLES, DEFAULT_EXAMPLE, resolveStep, applyChoice } from "./assistant.js";

const states = [{ example: DEFAULT_EXAMPLE }, ...Object.keys(ROLES).map((role) => applyChoice({}, { role }))];

test("every option leads to an existing step for every visitor role", () => {
  for (const state of states) {
    for (const stepId of Object.keys(STEPS)) {
      for (const option of resolveStep(stepId, state).options) {
        assert.ok(STEPS[option.go], `${stepId} → "${option.label}" points to missing step "${option.go}"`);
      }
    }
  }
});

test("no message leaks an unfilled placeholder", () => {
  for (const state of states) {
    for (const stepId of Object.keys(STEPS)) {
      for (const message of resolveStep(stepId, state).messages) {
        assert.doesNotMatch(message, /undefined|\$\{/, `${stepId}: ${message}`);
      }
    }
  }
});

test("choosing a role personalises the examples", () => {
  const state = applyChoice({}, { role: "arriendos" });
  assert.match(resolveStep("disputa", state).messages[0], /contrato de arriendo/);
});

test("unknown step is rejected by name", () => {
  assert.throws(() => resolveStep("precio", {}), /"precio" does not exist/);
});
