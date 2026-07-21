# internal/enterprise — reserved namespace (open-core boundary, D21/T-021)

This tree is reserved for **non-open** code: the managed Hub, compliance packs, and the
multi-tenant control plane (D21). None of it exists yet — this directory is drawn now, while it is
cheap, so the first commit of managed code lands on the correct side of a boundary that already
exists rather than having the boundary drawn around it afterwards.

**The rule, one-way and enforced by CI** (`scripts/check-opencore-boundary.sh`):

- No package OUTSIDE this tree may import anything INSIDE it. The open distribution must build
  without the managed code.
- Code inside this tree MAY import the open core. That asymmetry is what "open-core" means.

The check is proven to fire (`--selftest`) even though there is nothing here to guard yet, so its
green is meaningful from the first line of enterprise code.
