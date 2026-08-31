// Tests for Bug 4 (scale) fix: sqlBatched() id-batch pagination + boundedPool()
// concurrency. These prove the pagination/concurrency logic is correct without
// a live DB — acceptance requires the architect to run live.
import { test } from "node:test";
import assert from "node:assert/strict";
import { sqlBatched, boundedPool } from "../scripts/audit.js";

// --- sqlBatched: list+detail id-batch pagination ---

test("sqlBatched: single batch — list + detail merge", async () => {
  // 3 oids, batch size 25 → 1 detail call, all rows merged.
  const calls = [];
  const mockSql = async (token, ref, query) => {
    calls.push(query);
    if (query.startsWith("LIST")) {
      return [{ oid: 1 }, { oid: 2 }, { oid: 3 }];
    }
    // detail query — extract the oid array to simulate per-batch detail
    const m = query.match(/ARRAY\[([0-9,]+)\]/);
    const oids = m[1].split(",").map(Number);
    return oids.map((oid) => ({ oid, detail: true, function_name: `fn_${oid}` }));
  };
  const rows = await sqlBatched("tok", "ref", "LIST", "DETAIL __OID_BATCH__", 25, mockSql);
  assert.equal(calls.length, 2, "expected 1 list + 1 detail call");
  assert.equal(rows.length, 3, "all 3 detail rows returned");
  assert.deepEqual(rows.map((r) => r.oid), [1, 2, 3]);
  assert.equal(rows.every((r) => r.detail), true);
});

test("sqlBatched: multiple batches — chunks oids into pages of batchSize", async () => {
  // 60 oids, batch size 25 → 3 detail calls (25, 25, 10).
  const detailCalls = [];
  const allOids = Array.from({ length: 60 }, (_, i) => ({ oid: i + 1 }));
  const mockSql = async (token, ref, query) => {
    if (query.startsWith("LIST")) return allOids;
    const m = query.match(/ARRAY\[([0-9,]+)\]/);
    const batchOids = m[1].split(",").map(Number);
    detailCalls.push(batchOids);
    return batchOids.map((oid) => ({ oid, name: `obj_${oid}` }));
  };
  const rows = await sqlBatched("tok", "ref", "LIST", "DETAIL __OID_BATCH__", 25, mockSql);
  assert.equal(detailCalls.length, 3, "expected 3 detail batches");
  assert.equal(detailCalls[0].length, 25);
  assert.equal(detailCalls[1].length, 25);
  assert.equal(detailCalls[2].length, 10, "last batch is the remainder");
  assert.equal(rows.length, 60, "all 60 rows merged");
  assert.deepEqual(rows.map((r) => r.oid), allOids.map((r) => r.oid));
});

test("sqlBatched: empty list → no detail calls, returns []", async () => {
  let detailCalled = false;
  const mockSql = async (_, __, query) => {
    if (query.startsWith("LIST")) return [];
    detailCalled = true;
    return [];
  };
  const rows = await sqlBatched("tok", "ref", "LIST", "DETAIL __OID_BATCH__", 25, mockSql);
  assert.equal(detailCalled, false, "detail must NOT be called when list is empty");
  assert.deepEqual(rows, []);
});

test("sqlBatched: short page (less than batchSize) — stops after 1 batch", async () => {
  const mockSql = async (_, __, query) => {
    if (query.startsWith("LIST")) return [{ oid: 10 }, { oid: 20 }];
    return [{ oid: 10, ok: true }, { oid: 20, ok: true }];
  };
  const rows = await sqlBatched("tok", "ref", "LIST", "DETAIL __OID_BATCH__", 25, mockSql);
  assert.equal(rows.length, 2);
});

test("sqlBatched: empty detail result — returns [] but no error", async () => {
  const mockSql = async (_, __, query) => {
    if (query.startsWith("LIST")) return [{ oid: 1 }, { oid: 2 }];
    return []; // detail returns nothing
  };
  const rows = await sqlBatched("tok", "ref", "LIST", "DETAIL __OID_BATCH__", 25, mockSql);
  assert.deepEqual(rows, []);
});

test("sqlBatched: oids validated as safe integers — rejects non-numeric", async () => {
  // If the list somehow returns non-numeric oids, they must be filtered out
  // to prevent injection via the ARRAY[...] interpolation.
  const detailCalls = [];
  const mockSql = async (_, __, query) => {
    if (query.startsWith("LIST")) return [{ oid: 1 }, { oid: "evil'; DROP TABLE" }, { oid: 3 }];
    const m = query.match(/ARRAY\[([0-9,]+)\]/);
    detailCalls.push(m[1]);
    return [{ ok: true }];
  };
  await sqlBatched("tok", "ref", "LIST", "DETAIL __OID_BATCH__", 25, mockSql);
  assert.equal(detailCalls.length, 1, "single batch of only valid oids");
  assert.equal(detailCalls[0], "1,3", "non-numeric oid filtered out, no injection");
});

test("sqlBatched: __OID_BATCH__ placeholder replaced with ARRAY[oids]", async () => {
  let detailQuerySeen = "";
  const mockSql = async (_, __, query) => {
    if (query.startsWith("LIST")) return [{ oid: 5 }];
    detailQuerySeen = query;
    return [];
  };
  await sqlBatched("tok", "ref", "LIST", "SELECT * FROM t WHERE oid = ANY(__OID_BATCH__)", 25, mockSql);
  assert.equal(detailQuerySeen, "SELECT * FROM t WHERE oid = ANY(ARRAY[5])");
});

// --- boundedPool: concurrency + ordering ---

test("boundedPool: preserves result order regardless of completion order", async () => {
  const tasks = [0, 1, 2, 3, 4, 5, 6, 7].map((n) => {
    return () => new Promise((resolve) => {
      // Tasks with higher delay finish later, but results must keep order.
      setTimeout(() => resolve(n * 10), (3 - (n % 4)) * 10);
    });
  });
  const results = await boundedPool(tasks, 4);
  assert.equal(results.length, 8);
  assert.deepEqual(results, [0, 10, 20, 30, 40, 50, 60, 70]);
});

test("boundedPool: never exceeds concurrency limit", async () => {
  let active = 0;
  let maxActive = 0;
  const tasks = Array.from({ length: 12 }, (_, i) => {
    return () => new Promise((resolve) => {
      active++;
      maxActive = Math.max(maxActive, active);
      setTimeout(() => {
        active--;
        resolve(i);
      }, 20);
    });
  });
  await boundedPool(tasks, 4);
  assert.ok(maxActive <= 4, `max concurrent=${maxActive}, expected <= 4`);
});

test("boundedPool: concurrency defaults to 6 when omitted", async () => {
  let active = 0;
  let maxActive = 0;
  const tasks = Array.from({ length: 20 }, (_, i) => {
    return () => new Promise((resolve) => {
      active++;
      maxActive = Math.max(maxActive, active);
      setTimeout(() => {
        active--;
        resolve(i);
      }, 10);
    });
  });
  await boundedPool(tasks);
  assert.ok(maxActive <= 6, `default max concurrent=${maxActive}, expected <= 6`);
});

test("boundedPool: empty tasks → empty results", async () => {
  const results = await boundedPool([]);
  assert.deepEqual(results, []);
});

test("boundedPool: single task → returns array of 1", async () => {
  const results = await boundedPool([() => Promise.resolve("done")]);
  assert.deepEqual(results, ["done"]);
});

test("boundedPool: errors propagate (rejects)", async () => {
  const tasks = [
    () => Promise.resolve("ok"),
    () => Promise.reject(new Error("boom")),
    () => Promise.resolve("late"),
  ];
  await assert.rejects(boundedPool(tasks, 2), { message: "boom" });
});
