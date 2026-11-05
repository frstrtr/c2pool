# archive/xmr-option-a

Status: not built. No CMake file and no source list names this directory.

Last commit where it was live: tag `archive/xmr-option-a`.

## Files

| file | source path at the tag | source lines at the tag |
|---|---|---|
| `xmr_o2_template.hpp` | `src/c2pool/v37/xmr/xmr_o2_template.hpp` | whole file |
| `main_v37_xmr.cpp.fragment` | `src/c2pool/v37/main_v37_xmr.cpp` | 93; 506; 508-510; 6096-6119; 6297; 6304-6309; 6612; 6616 |
| `xmr_node_config.hpp.fragment` | `src/c2pool/v37/xmr/xmr_node_config.hpp` | 107; 153-159; 267-270; 291-297; 585-587 |

A fragment file is its source lines in the order listed, byte for byte.

## Restore

The whole tree as it was:

    git checkout archive/xmr-option-a

Onto a later tree: copy `xmr_o2_template.hpp` to `src/c2pool/v37/xmr/` and put each fragment back at its source lines.
Inputs a restore re-adds: `--coinbase monerod`, `--template-reserve`, `--share-diff`.
