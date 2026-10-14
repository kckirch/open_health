This is oura-link from Th0rgal/open_oura at
4f7957d3304c4084f0e1e703f3d84606bf10b781, with the first-sync timestamp fix
from https://github.com/Th0rgal/open_oura/pull/28 (sylphrena0), plus a regression
test and rejected/replayed event counts in the empty-batch error.

The first retained event anchors a sync starting at cursor zero. Existing
checkpoints still bound timestamp jumps and replayed events remain excluded.
The upstream MIT license is included. Remove this local patch when the shared
dependency includes a verified equivalent fix.
