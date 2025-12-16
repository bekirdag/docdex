"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const { ManifestResolutionError, resolveCanonicalAssetForTargetTriple } = require("../lib/release_manifest");

test("resolves from manifest.targets map deterministically", () => {
  const manifest = {
    targets: {
      "x86_64-unknown-linux-gnu": {
        asset: { name: "docdexd-linux-x64-gnu.tar.gz", id: 123 },
        integrity: { sha256: "a".repeat(64) }
      }
    }
  };

  const resolved = resolveCanonicalAssetForTargetTriple(manifest, "x86_64-unknown-linux-gnu");
  assert.equal(resolved.asset.name, "docdexd-linux-x64-gnu.tar.gz");
  assert.equal(resolved.asset.id, 123);
  assert.equal(resolved.integrity.sha256, "a".repeat(64));
});

test("resolves from manifest.assets array with alternate field names", () => {
  const manifest = {
    assets: [
      {
        target_triple: "aarch64-apple-darwin",
        name: "docdexd-darwin-arm64.tar.gz",
        sha256: "b".repeat(64)
      }
    ]
  };

  const resolved = resolveCanonicalAssetForTargetTriple(manifest, "aarch64-apple-darwin");
  assert.equal(resolved.asset.name, "docdexd-darwin-arm64.tar.gz");
  assert.equal(resolved.integrity.sha256, "b".repeat(64));
});

test("no-match throws actionable error with supported list", () => {
  const manifest = {
    targets: {
      "x86_64-unknown-linux-gnu": {
        asset: "docdexd-linux-x64-gnu.tar.gz",
        sha256: "c".repeat(64)
      },
      "x86_64-unknown-linux-musl": {
        asset: "docdexd-linux-x64-musl.tar.gz",
        sha256: "d".repeat(64)
      }
    }
  };

  assert.throws(
    () => resolveCanonicalAssetForTargetTriple(manifest, "aarch64-unknown-linux-gnu"),
    (err) => {
      assert.ok(err instanceof ManifestResolutionError);
      assert.equal(err.code, "DOCDEX_ASSET_NO_MATCH");
      assert.deepEqual(err.details.supported, ["x86_64-unknown-linux-gnu", "x86_64-unknown-linux-musl"]);
      assert.equal(err.details.manifestVersion, null);
      assert.equal(err.details.assetName, null);
      return true;
    }
  );
});

test("multi-match throws deterministic error", () => {
  const manifest = {
    assets: [
      {
        target: "x86_64-pc-windows-msvc",
        asset: "docdexd-win32-x64.tar.gz",
        sha256: "e".repeat(64)
      },
      {
        target: "x86_64-pc-windows-msvc",
        asset: "docdexd-win32-x64-alt.tar.gz",
        sha256: "f".repeat(64)
      }
    ]
  };

  assert.throws(
    () => resolveCanonicalAssetForTargetTriple(manifest, "x86_64-pc-windows-msvc"),
    (err) => {
      assert.ok(err instanceof ManifestResolutionError);
      assert.equal(err.code, "DOCDEX_ASSET_MULTI_MATCH");
      assert.deepEqual(err.details.matches, ["docdexd-win32-x64-alt.tar.gz", "docdexd-win32-x64.tar.gz"]);
      assert.equal(err.details.manifestVersion, null);
      assert.equal(err.details.assetName, null);
      return true;
    }
  );
});

test("missing sha256 throws actionable error", () => {
  const manifest = {
    targets: {
      "x86_64-unknown-linux-gnu": {
        asset: "docdexd-linux-x64-gnu.tar.gz"
      }
    }
  };

  assert.throws(
    () => resolveCanonicalAssetForTargetTriple(manifest, "x86_64-unknown-linux-gnu"),
    (err) => {
      assert.ok(err instanceof ManifestResolutionError);
      assert.equal(err.code, "DOCDEX_ASSET_MALFORMED");
      assert.equal(err.details.manifestVersion, null);
      assert.equal(err.details.assetName, "docdexd-linux-x64-gnu.tar.gz");
      return true;
    }
  );
});

test("non-object manifest throws schema error deterministically", () => {
  assert.throws(
    () => resolveCanonicalAssetForTargetTriple([], "x86_64-unknown-linux-gnu"),
    (err) => {
      assert.ok(err instanceof ManifestResolutionError);
      assert.equal(err.code, "DOCDEX_MANIFEST_MALFORMED");
      assert.match(err.message, /^Malformed manifest: expected a JSON object at top-level/);
      assert.equal(err.details.manifestVersion, null);
      return true;
    }
  );
});

test("manifestVersion is surfaced in errors (schemaVersion/version aliases)", () => {
  assert.throws(
    () =>
      resolveCanonicalAssetForTargetTriple(
        {
          schemaVersion: 7,
          targets: {}
        },
        "x86_64-unknown-linux-gnu"
      ),
    (err) => {
      assert.ok(err instanceof ManifestResolutionError);
      assert.equal(err.code, "DOCDEX_ASSET_NO_MATCH");
      assert.equal(err.details.manifestVersion, 7);
      return true;
    }
  );

  assert.throws(
    () =>
      resolveCanonicalAssetForTargetTriple(
        {
          version: "v2",
          assets: []
        },
        "x86_64-unknown-linux-gnu"
      ),
    (err) => {
      assert.ok(err instanceof ManifestResolutionError);
      assert.equal(err.code, "DOCDEX_ASSET_NO_MATCH");
      assert.equal(err.details.manifestVersion, "v2");
      return true;
    }
  );
});

test("malformed sha256 is treated as missing integrity metadata", () => {
  assert.throws(
    () =>
      resolveCanonicalAssetForTargetTriple(
        {
          targets: {
            "x86_64-unknown-linux-gnu": {
              asset: "docdexd-linux-x64-gnu.tar.gz",
              integrity: { sha256: "NOT_A_SHA" }
            }
          }
        },
        "x86_64-unknown-linux-gnu"
      ),
    (err) => {
      assert.ok(err instanceof ManifestResolutionError);
      assert.equal(err.code, "DOCDEX_ASSET_MALFORMED");
      assert.equal(err.details.assetName, "docdexd-linux-x64-gnu.tar.gz");
      return true;
    }
  );
});

test("missing canonical asset identifier triggers actionable schema error", () => {
  assert.throws(
    () =>
      resolveCanonicalAssetForTargetTriple(
        {
          targets: {
            "x86_64-unknown-linux-gnu": {
              asset: { id: 123 },
              integrity: { sha256: "a".repeat(64) }
            }
          }
        },
        "x86_64-unknown-linux-gnu"
      ),
    (err) => {
      assert.ok(err instanceof ManifestResolutionError);
      assert.equal(err.code, "DOCDEX_ASSET_MALFORMED");
      assert.match(err.message, /missing a canonical asset name\/identifier/);
      assert.equal(err.details.assetName, null);
      return true;
    }
  );
});

test("non-object manifest throws schema error deterministically", () => {
  assert.throws(
    () => resolveCanonicalAssetForTargetTriple([], "x86_64-unknown-linux-gnu"),
    (err) => {
      assert.ok(err instanceof ManifestResolutionError);
      assert.equal(err.code, "DOCDEX_MANIFEST_MALFORMED");
      assert.match(err.message, /^Malformed manifest: expected a JSON object at top-level/);
      assert.equal(err.details.manifestVersion, null);
      return true;
    }
  );
});

test("manifestVersion is surfaced in errors (schemaVersion/version aliases)", () => {
  assert.throws(
    () =>
      resolveCanonicalAssetForTargetTriple(
        {
          schemaVersion: 7,
          targets: {}
        },
        "x86_64-unknown-linux-gnu"
      ),
    (err) => {
      assert.ok(err instanceof ManifestResolutionError);
      assert.equal(err.code, "DOCDEX_ASSET_NO_MATCH");
      assert.equal(err.details.manifestVersion, 7);
      return true;
    }
  );

  assert.throws(
    () =>
      resolveCanonicalAssetForTargetTriple(
        {
          version: "v2",
          assets: []
        },
        "x86_64-unknown-linux-gnu"
      ),
    (err) => {
      assert.ok(err instanceof ManifestResolutionError);
      assert.equal(err.code, "DOCDEX_ASSET_NO_MATCH");
      assert.equal(err.details.manifestVersion, "v2");
      return true;
    }
  );
});

test("malformed sha256 is treated as missing integrity metadata", () => {
  assert.throws(
    () =>
      resolveCanonicalAssetForTargetTriple(
        {
          targets: {
            "x86_64-unknown-linux-gnu": {
              asset: "docdexd-linux-x64-gnu.tar.gz",
              integrity: { sha256: "NOT_A_SHA" }
            }
          }
        },
        "x86_64-unknown-linux-gnu"
      ),
    (err) => {
      assert.ok(err instanceof ManifestResolutionError);
      assert.equal(err.code, "DOCDEX_ASSET_MALFORMED");
      assert.equal(err.details.assetName, "docdexd-linux-x64-gnu.tar.gz");
      return true;
    }
  );
});

test("missing canonical asset identifier triggers actionable schema error", () => {
  assert.throws(
    () =>
      resolveCanonicalAssetForTargetTriple(
        {
          targets: {
            "x86_64-unknown-linux-gnu": {
              asset: { id: 123 },
              integrity: { sha256: "a".repeat(64) }
            }
          }
        },
        "x86_64-unknown-linux-gnu"
      ),
    (err) => {
      assert.ok(err instanceof ManifestResolutionError);
      assert.equal(err.code, "DOCDEX_ASSET_MALFORMED");
      assert.match(err.message, /missing a canonical asset name\/identifier/);
      assert.equal(err.details.assetName, null);
      return true;
    }
  );
});
