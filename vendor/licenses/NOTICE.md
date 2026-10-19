# Upstream notices

The adjacent license files are verbatim upstream notices:

- **wireproxy v1.1.3**, ISC: <https://github.com/windtf/wireproxy/tree/v1.1.3>.
- **wgcf v2.3.1**, MIT: <https://github.com/ViRb3/wgcf/tree/v2.3.1>.
- **ros-scripts**, MIT, commit `d92d68db030e833c7f6032697e4f177dfe976230`:
  <https://github.com/Viktor45/ros-scripts/tree/d92d68db030e833c7f6032697e4f177dfe976230>.
  WarpPocket's static endpoint/port lists are derived from `warp-finder/` at
  this revision, not from a moving branch or remote runtime configuration.

`../wireproxy-build.json` pins the wireproxy source archive and WireGuard module.
Go preparation verifies the source digest and patches isolated copies under
`build/deps`, not the global module cache. No standalone wireproxy/wgcf executable
is shipped: the engine runs from WarpPocket's own EXE, and the native WARP API
retains the wgcf protocol/TLS behavior. Distributions containing derived code or
lists retain these notices. The application's embedded
`internal/resources/licenses.txt` also includes Gio, dependencies, fonts, CA data
and Go standard-library notices; it is accessible from the Settings menu.
