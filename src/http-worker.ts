import { parentPort } from "node:worker_threads";
import { serveParsed } from "./http-serve.js";

type Job = { authorization: string; url: string; headers: [string, string][]; body: unknown };

parentPort!.on("message", async (job: Job) => {
  try {
    const reply = await serveParsed(job.authorization, job.url, job.headers, job.body);
    parentPort!.postMessage({ ok: true, reply }, reply.body ? [reply.body] : []);
  } catch {
    parentPort!.postMessage({ ok: false });
  }
});
