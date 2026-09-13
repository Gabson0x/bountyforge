# FV-VYP-9-C1 Unbounded Loops

## TLDR

Vyper requires loop bounds to be statically known at compile time, but a loop over a `DynArray` iterates up to the declared maximum length, which can be reached at runtime. When the array grows through user-controlled appends, the gas cost of any function that iterates the full array grows proportionally, eventually exceeding the block gas limit and permanently bricking the operation.

## Detection Heuristics

**`for` loop over a `DynArray` populated by untrusted callers**
- `for recipient in self.recipients:` where `self.recipients` is a `DynArray[address, N]` that any caller can append to via a public `join` or `register` function
- `for participant in self.participants:` inside `distribute_rewards` or `settle` where `self.participants` grows unboundedly

**Large declared `DynArray` maximum combined with full iteration**
- `DynArray[address, 1000]` or larger used as the type for a list that is fully iterated in a single function call
- The declared maximum (`N`) in `DynArray[T, N]` is large enough that iterating all `N` elements would consume more than the block gas limit at realistic per-iteration cost

**Array compaction via full-scan removal**
- Element removal implemented by iterating the entire array to rebuild it without the target element: `for item in self.items: if item != target: new_list.append(item)`
- No O(1) swap-and-pop pattern used; removal cost grows linearly with array length

**Accumulation inside a loop with no batch-processing mechanism**
- A single function iterates the full list and writes to storage for every element: `self.balances[p] += reward` inside a loop with no `start_index` / `batch_size` pagination
- No `distribution_index` or equivalent cursor to resume a partial iteration in a subsequent transaction

**Loop bounds derived from storage length at call time**
- `for i in range(len(self.list)):` where `len` is evaluated at call time and the list may have grown since deployment

## False Positives

- `DynArray` with a small declared maximum (e.g., `DynArray[address, 10]`) where the worst-case gas cost per call is bounded and well within the block gas limit
- Loop iteration where the declared maximum is enforced by a require in the append function and the per-iteration gas cost is low and audited
- Batch processing functions with explicit `start: uint256` and `end: uint256` parameters that allow callers to iterate a subset of the array across multiple transactions