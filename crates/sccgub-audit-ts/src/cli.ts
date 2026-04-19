#!/usr/bin/env node
/**
 * sccgub-audit-ts CLI.
 *
 * Mirrors the Rust binary's surface per PATCH_08 §C.4 + PATCH_09 §C.5.
 *
 * Subcommand:
 *     verify-ceilings --chain-state <path> [--json] [--conformance]
 *
 * Exit codes (matching Rust + Python):
 *     0 = Ok (verifier returned null)
 *     1 = CeilingViolation
 *     2 = malformed input or I/O error
 *
 * Per PATCH_09 §C.5 the entry-point script is `sccgub-audit-ts`
 * (the `-ts` suffix avoids name collision with the Rust and Python
 * binaries in operator environments where multiple are installed).
 */

import { pathToFileURL } from "node:url";

import { loadFixtureFromJson } from "./chainState.js";
import { verifyCeilingsUnchangedSinceGenesis } from "./verifier.js";
import {
  type CeilingViolation,
  violationKind,
  violationToString,
} from "./violation.js";

interface ParsedArgs {
  command: "verify-ceilings" | "help";
  chainState?: string;
  json: boolean;
  conformance: boolean;
}

function parseArgs(argv: readonly string[]): ParsedArgs {
  const args = [...argv];
  if (args.length === 0 || args[0] === "--help" || args[0] === "-h") {
    return { command: "help", json: false, conformance: false };
  }
  const command = args.shift();
  if (command !== "verify-ceilings") {
    process.stderr.write(`unknown command: ${command}\n`);
    return { command: "help", json: false, conformance: false };
  }
  let chainState: string | undefined;
  let json = false;
  let conformance = false;
  while (args.length > 0) {
    const flag = args.shift();
    switch (flag) {
      case "--chain-state": {
        const next = args.shift();
        if (next === undefined) {
          throw new Error("--chain-state requires a path argument");
        }
        chainState = next;
        break;
      }
      case "--json":
        json = true;
        break;
      case "--conformance":
        conformance = true;
        break;
      default:
        throw new Error(`unknown flag: ${flag}`);
    }
  }
  if (chainState === undefined) {
    throw new Error("--chain-state is required");
  }
  return { command: "verify-ceilings", chainState, json, conformance };
}

function printUsage(): void {
  process.stderr.write(
    `sccgub-audit-ts — TypeScript port of the SCCGUB moat verifier\n\n` +
      `Usage:\n` +
      `  sccgub-audit-ts verify-ceilings --chain-state <path> [--json] [--conformance]\n\n` +
      `Per PATCH_08.md and POSITIONING.md §11. Pure stdlib (Node built-ins),\n` +
      `dependency-isolated by design.\n`,
  );
}

export function main(argv: readonly string[] = process.argv.slice(2)): number {
  let args: ParsedArgs;
  try {
    args = parseArgs(argv);
  } catch (e) {
    process.stderr.write(`INPUT ERROR: ${(e as Error).message}\n`);
    printUsage();
    return 2;
  }
  if (args.command === "help") {
    printUsage();
    return 2;
  }
  return verifyCeilingsCommand(args.chainState!, args.json, args.conformance);
}

function verifyCeilingsCommand(
  chainStatePath: string,
  jsonOutput: boolean,
  conformance: boolean,
): number {
  let fixture;
  try {
    fixture = loadFixtureFromJson(chainStatePath);
  } catch (e) {
    emitInputError(jsonOutput, conformance, errorMessage(e));
    return 2;
  }
  const result = verifyCeilingsUnchangedSinceGenesis(fixture);
  if (result === null) {
    emitOk(jsonOutput, conformance);
    return 0;
  }
  emitViolation(jsonOutput, conformance, result);
  return 1;
}

function emitOk(jsonOutput: boolean, conformance: boolean): void {
  if (conformance) {
    // Per PATCH_09 §E.2 expected-output format.
    process.stdout.write("ok\n");
  } else if (jsonOutput) {
    process.stdout.write(
      JSON.stringify({ result: "ok", message: "ceilings unchanged since genesis" }) + "\n",
    );
  } else {
    process.stdout.write("OK: ceilings unchanged since genesis. Moat HELD.\n");
  }
}

function emitViolation(
  jsonOutput: boolean,
  conformance: boolean,
  v: CeilingViolation,
): void {
  if (conformance) {
    // Per PATCH_09 §E.2 expected-output format.
    const kind = violationKind(v);
    if (v.kind === "FieldValueChanged") {
      process.stdout.write(
        `violation:${kind}:transition_height=${v.transition_height}:` +
          `ceiling_field=${v.ceiling_field}:` +
          `before_value=${v.before_value}:after_value=${v.after_value}\n`,
      );
    } else if (v.kind === "CeilingsUnreadableAtTransition") {
      process.stdout.write(
        `violation:${kind}:transition_height=${v.transition_height}\n`,
      );
    } else {
      process.stdout.write(`violation:${kind}\n`);
    }
  } else if (jsonOutput) {
    process.stdout.write(
      JSON.stringify({ result: "violation", violation: violationToJson(v) }) + "\n",
    );
  } else {
    process.stdout.write(`VIOLATION: ${violationToString(v)}\n`);
  }
}

function violationToJson(v: CeilingViolation): Record<string, unknown> {
  switch (v.kind) {
    case "FieldValueChanged":
      return {
        kind: "FieldValueChanged",
        transition_height: v.transition_height.toString(),
        ceiling_field: v.ceiling_field,
        before_value: v.before_value.toString(),
        after_value: v.after_value.toString(),
      };
    case "GenesisCeilingsUnreadable":
      return { kind: "GenesisCeilingsUnreadable", reason: v.reason };
    case "CeilingsUnreadableAtTransition":
      return {
        kind: "CeilingsUnreadableAtTransition",
        transition_height: v.transition_height.toString(),
        reason: v.reason,
      };
    case "HistoryStructurallyInvalid":
      return { kind: "HistoryStructurallyInvalid", reason: v.reason };
  }
}

function emitInputError(
  jsonOutput: boolean,
  conformance: boolean,
  msg: string,
): void {
  if (conformance) {
    // Conformance protocol does not have an explicit "input-error"
    // line; emit nothing on stdout and only surface on stderr so
    // the cross-language harness still diffs cleanly. Real failures
    // are caught via exit code 2.
    process.stderr.write(`INPUT ERROR: ${msg}\n`);
  } else if (jsonOutput) {
    process.stderr.write(
      JSON.stringify({ result: "input_error", message: msg }) + "\n",
    );
  } else {
    process.stderr.write(`INPUT ERROR: ${msg}\n`);
  }
}

function errorMessage(e: unknown): string {
  if (e instanceof Error) {
    return e.message;
  }
  return String(e);
}

// Entry point — only run when invoked as the script, not when imported.
// Uses pathToFileURL to handle Windows path/URL encoding (backslash vs.
// percent-encoded forward slash), spaces in paths, and drive letters
// uniformly.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exit(main());
}
