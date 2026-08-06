# Tasks — CONSOLE-9

- [x] 1. `xdr.Store.Entities` — newest-first, page counts ENTITIES not rows, capped.
- [x] 2. `xdr.Store.EntityFor` — all aliases of the matched entity; does not create on miss.
- [x] 3. `EntitiesWithRisk` / `EntityFor` on the Server, risk as a nullable.
- [x] 4. `GET /entities` (+ `?value=`, `?window=`, `?limit=`), analyst tier, mounted.
- [x] 5. Package tests + mutations: risk absent vs zero; read does not create; 404 vs empty; alias
      completeness; page counts entities; malformed window refused.
- [x] 6. Integration test against the shipped binary.
- [x] 7. Docs: decision row, roadmap status.
