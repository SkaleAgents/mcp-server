import { Worker } from "node:worker_threads";
import type { ServedReply } from "./http-serve.js";

export class PoolBusy extends Error {}
export class PoolTimeout extends Error {}

type Task = {
  message: unknown;
  resolve: (reply: ServedReply) => void;
  reject: (error: Error) => void;
};

/** Keeps CPU-heavy MCP tool calls off the host's event loop, with a time limit per request. */
export class WorkerPool {
  private idle: Worker[] = [];
  private running = 0;
  private queue: Task[] = [];

  constructor(
    private readonly file: URL,
    private readonly size: number,
    private readonly timeoutMs: number,
    private readonly maxQueue: number,
  ) {}

  run(message: unknown): Promise<ServedReply> {
    return new Promise((resolve, reject) => {
      if (this.queue.length >= this.maxQueue) return reject(new PoolBusy());
      this.queue.push({ message, resolve, reject });
      this.drain();
    });
  }

  private drain() {
    while (this.queue.length && (this.idle.length || this.running < this.size)) {
      const task = this.queue.shift()!;
      const reused = this.idle.pop();
      const worker = reused ?? new Worker(this.file);
      if (!reused) this.running++;
      this.assign(worker, task);
    }
  }

  private assign(worker: Worker, task: Task) {
    let settled = false;
    const finish = (healthy: boolean) => {
      settled = true;
      clearTimeout(timer);
      worker.off("message", onMessage);
      worker.off("error", onFailure);
      worker.off("exit", onFailure);
      if (healthy) {
        // An idle worker must not keep the host process alive.
        worker.unref();
        this.idle.push(worker);
      }
      else {
        this.running--;
        void worker.terminate();
      }
      this.drain();
    };
    const onMessage = (result: { ok: boolean; reply?: ServedReply }) => {
      if (settled) return;
      finish(true);
      if (result.ok && result.reply) task.resolve(result.reply);
      else task.reject(new Error("mcp_request_failed"));
    };
    const onFailure = () => {
      if (settled) return;
      finish(false);
      task.reject(new Error("mcp_worker_failed"));
    };
    const timer = setTimeout(() => {
      if (settled) return;
      finish(false);
      task.reject(new PoolTimeout());
    }, this.timeoutMs);
    worker.ref();
    worker.on("message", onMessage);
    worker.once("error", onFailure);
    worker.once("exit", onFailure);
    worker.postMessage(task.message);
  }
}
