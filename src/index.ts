#!/usr/bin/env node
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createServer } from "./server.js";

createServer()
  .connect(new StdioServerTransport())
  .catch((error: unknown) => {
    console.error(error);
    process.exit(1);
  });
