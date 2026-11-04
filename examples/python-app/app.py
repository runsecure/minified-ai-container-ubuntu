"""Example workload: numpy on OpenBLAS worker threads."""
import os
import time

import numpy as np

rng = np.random.default_rng(0)
a = rng.standard_normal((1024, 1024))

t = time.perf_counter()
for _ in range(10):
    b = a @ a.T  # BLAS dgemm, multi-threaded
eig = np.linalg.eigvalsh(b)
dt = time.perf_counter() - t

assert np.allclose(b, b.T) and eig.min() > -1e-6, "unexpected linear-algebra result"
blas = np.show_config(mode="dicts")["Build Dependencies"]["blas"]["name"]
print(f"numpy {np.__version__} ({blas}) on {os.cpu_count()} CPUs: "
      f"10x 1024^2 matmul + eigvalsh in {dt:.2f}s, max eigenvalue {eig.max():.1f}")
