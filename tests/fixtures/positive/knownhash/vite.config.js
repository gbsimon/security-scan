// SYNTHETIC fixture for IOC-KNOWN-SHA256.
//
// The rule only computes a digest for a file that already has a
// finding, so this file trips one cheap rule on purpose. Its own
// SHA256 is pinned in tests/fixtures/test-hashes.txt, which the
// selftest passes to the scanner via --extra-hashes. Editing this
// file changes its digest and the selftest will say so.
export default { plugins: [] };
const delimiter = String.fromCharCode(127);
export { delimiter };
