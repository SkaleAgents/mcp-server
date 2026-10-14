#!/usr/bin/env node
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { runScan } from "./cli.js";
import { createServer } from "./server.js";

if (process.argv[2] === "scan") {
  runScan(process.argv.slice(3)).then(
    (code) => process.exit(code),
    (error: unknown) => {
      console.error(error instanceof Error ? error.message : error);
      // Exit 2 would block the agent's stop, so a broken hook stays out of the way.
      process.exit(process.argv.includes("--hook") ? 0 : 2);
    },
  );
} else {
  createServer()
    .connect(new StdioServerTransport())
    .catch((error: unknown) => {
      console.error(error);
      process.exit(1);
    });
}
