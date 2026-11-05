# Log 04 — Q&A: chunked / out-of-core training (re: log 02 §3.3)

- **Date:** 2026-11-05
- **Query:** "Some Python libraries load data chunk by chunk so ML still works. Am I right? Why didn't you recommend it? Is the overhead large?"
- **Files changed:** log 02 (correction note at §3.3), `claude-notes/project-status.md` (data-loading decision). No code.

## 1. Short answer
**Yes, you're right.** This is called **out-of-core** (or external-memory) learning. My log 02 RAM argument was **overstated**. I computed the size of the *raw float32 matrix* (~13 GB), but LightGBM never needs that matrix in RAM at once. The subset decision still stands, for different reasons (§4).

## 2. The options, from most to least relevant for us

### 2.1 LightGBM `Sequence`: chunked dataset construction (best fit)
A GBDT doesn't train on raw floats. Before training, LightGBM **bins** each feature: it picks ≤ 255 cut points per feature, so each value becomes a `uint8` bin index. Training then only touches the bins (histogram-based split finding).

The `lightgbm.Sequence` interface (an abstract class: `__getitem__`, `__len__`, `batch_size`) lets `lgb.Dataset` pull rows **in batches** from any source, such as our `np.memmap` files on disk. Construction is roughly two passes:
1. **Sample** about `bin_construct_sample_cnt` rows (default 200 k) to choose the bin boundaries per feature.
2. **Stream** all rows batch by batch and write their bin indices.

After that, the raw matrix can be dropped. Memory math for the full Win32 train set:

| Representation | Bytes/value | 1.3 M × 2568 |
|----------------|-------------|--------------|
| float32 raw (what I computed in log 02) | 4 | ≈ 13 GB ❌ |
| LightGBM binned dense | 1 | ≈ 3.3 GB ✅ |
| LightGBM binned, sparse features | < 1 | less. Hashed import/export bins are mostly zeros, and LightGBM stores mostly-zero columns sparsely. |

**Overhead:** only at construction time (one extra sequential read of the data, which is disk-bound and fast on an SSD). **Training itself runs at full in-memory speed**, because it trains on the binned in-RAM data. That's the overhead you asked about, and here it's close to zero.

C++ analogy: it's like coordinate compression. You can't keep 64-bit values, so you sort a sample, compress each value to its rank bucket, and work on the small integer array from then on.

### 2.2 XGBoost external memory (`ExtMemQuantileDMatrix` + a data iterator)
This is true external memory: XGBoost keeps the quantized pages on disk (or in host RAM for GPU training) and **streams them every boosting iteration**. That lowers RAM further, but each of the hundreds of iterations re-reads the pages, so **training becomes I/O-bound**. The cost is typically a few times slower than in-memory on CPU. It's worth it when even the binned data doesn't fit. Not our case.

### 2.3 scikit-learn `partial_fit` (true streaming / online learning)
`SGDClassifier`, `MultinomialNB`, `MiniBatchKMeans`, … take one chunk at a time and update their parameters. Memory is O(chunk) and overhead is nil. **The catch:** these are mostly **linear** models. On EMBER-style features, boosted trees clearly outperform them. Linear models also need feature scaling, which is another streaming pass (`StandardScaler.partial_fit`). So it's a correct technique, but the wrong model class for this data.

### 2.4 Things that look similar but aren't equivalent
- **Training a GBDT chunk by chunk with `init_model` / continued training:** each new set of trees only fits the residuals on the *current* chunk. That isn't the same as training on all data, and the model drifts toward the last chunks. Avoid it.
- **Dask / Spark:** for distributing work across machines. Pure overhead on one PC.

## 3. Why I didn't recommend it
Honestly, I should have mentioned it. I sized RAM by the raw matrix instead of by what the algorithm actually stores. The plan already used `np.memmap` (that is, `mmap`: the OS pages data in on demand) for *loading*, but I didn't connect it to LightGBM's chunked construction, which makes the full set trainable.

## 4. Does the Win32_test subset still make sense? Yes, for other reasons
| Cost | Win32_test (4.9 GB zip) | Win32_train (23.7 GB zip) |
|------|------------------------|---------------------------|
| Download | minutes | ~5× longer |
| Vectorize (JSON parse → 2568 floats per line, CPU-bound) | short | ~5× longer (likely hours) |
| Each training experiment | minutes | ~5× longer |

For a 2-day learning project, **fast iteration beats more data**. You'll retrain many times while learning about thresholds and splits. Out-of-core fixes *RAM*, not *time*.

## 5. Decision (updates the plan)
- The data loader will expose our memmapped vectors as a **`lightgbm.Sequence`**, never materializing the full float32 matrix.
- We start on Win32_test (temporal split by week). Moving to Win32_train later becomes **a config change, not a rewrite**: same code, more rows.
- Recorded in `claude-notes/project-status.md`. Log 02 §3.3 has a correction note pointing here.
